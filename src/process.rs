use crate::model::{ChatCompletion, Choice, Content, DuckChatCompletion, Message, Role, Usage};
use axum::response::{IntoResponse, Response, Sse, sse::Event};
use axum::{Error, Json};
use eventsource_stream::Eventsource;
use futures_util::{Stream, StreamExt};

type EventResult = Result<Event, axum::Error>;

#[derive(typed_builder::TypedBuilder)]
pub struct ChatProcess {
    stream: Option<bool>,
    model: String,
    resp: reqwest::Response,
}

impl ChatProcess {
    pub async fn into_response(self) -> crate::Result<Response> {
        if self.resp.error_for_status_ref().err().is_some() {
            let err = self.resp.text().await?;
            Err(crate::Error::BadRequest(err))
        } else {
            if self.stream.unwrap_or_default() {
                self.into_stream_response().await
            } else {
                self.into_single_response().await
            }
        }
    }

    async fn into_stream_response(self) -> crate::Result<Response> {
        let raw_model = self.model.clone();
        let mut first_message = true;
        let sse_stream = process_stream_with_chunk(
            self.resp,
            move |body: DuckChatCompletion| {
                let choice = if let Some(content) = body.message {
                    // only first message has role
                    let role = if first_message {
                        first_message = false;
                        Some(Role::Assistant)
                    } else {
                        None
                    };
                    Choice::builder()
                        .index(0)
                        .delta(
                            Message::builder()
                                .role(role)
                                .content(Content::Text(content))
                                .build(),
                        )
                        .logprobs(None)
                        .finish_reason(None)
                        .build()
                } else {
                    Choice::builder()
                        .index(0)
                        .delta(Message::default())
                        .logprobs(None)
                        .finish_reason("stop")
                        .build()
                };

                let chat_completion = ChatCompletion::builder()
                    .id(body.id)
                    .model(&raw_model)
                    .object("chat.completion.chunk")
                    .created(body.created)
                    .choices(vec![choice])
                    .build();

                Event::default()
                    .json_data(chat_completion)
                    .map_err(Error::new)
            },
            |event| Ok(Event::default().data(event.data)),
        );
        Ok(Sse::new(sse_stream).into_response())
    }

    async fn into_single_response(self) -> crate::Result<Response> {
        let mut id = None;
        let mut created = None;
        let mut model = None;
        let mut content = String::new();

        process_stream(self.resp, |body| {
            if id.is_none() {
                id = Some(body.id);
            }
            if created.is_none() {
                created = Some(body.created);
            }
            if model.is_none() {
                model = Some(body.model);
            }
            if let Some(message) = body.message {
                content.push_str(&message);
            }
        })
        .await;

        let chat_completion = ChatCompletion::builder()
            .id(id)
            .model(&self.model)
            .object("chat.completion")
            .created(created)
            .choices(vec![
                Choice::builder()
                    .index(0)
                    .message(
                        Message::builder()
                            .role(Role::Assistant)
                            .content(Content::Text(content))
                            .build(),
                    )
                    .logprobs(None)
                    .finish_reason("stop")
                    .build(),
            ])
            .usage(
                Usage::builder()
                    .completion_tokens(0)
                    .prompt_tokens(0)
                    .total_tokens(0)
                    .build(),
            )
            .build();

        Ok(Json(chat_completion).into_response())
    }
}

async fn process_stream<H>(resp: reqwest::Response, mut handler: H)
where
    H: FnMut(DuckChatCompletion),
{
    let mut event_source = resp.bytes_stream().eventsource();
    while let Some(event_result) = event_source.next().await {
        match event_result {
            Ok(event) => {
                if event.data == "[DONE]" {
                    break;
                }
                match serde_json::from_str::<DuckChatCompletion>(&event.data) {
                    Ok(body) => handler(body),
                    Err(err) => {
                        tracing::warn!("failed to parse upstream body: {err}");
                    }
                }
            }
            Err(err) => {
                tracing::warn!("failed read upstream bytes stream: {err}")
            }
        }
    }
}

fn process_stream_with_chunk<S, E>(
    resp: reqwest::Response,
    mut handler: S,
    end_handler: E,
) -> impl Stream<Item = EventResult>
where
    S: FnMut(DuckChatCompletion) -> EventResult,
    E: FnOnce(eventsource_stream::Event) -> EventResult,
{
    let mut event_source = resp.bytes_stream().eventsource();
    async_stream::stream! {
        while let Some(event_result) = event_source.next().await {
            match event_result {
                Ok(event) => {
                    if event.data == "[DONE]" {
                        yield end_handler(event);
                        break;
                    }
                    match serde_json::from_str::<DuckChatCompletion>(&event.data) {
                        Ok(body) => yield handler(body),
                        Err(err) => {
                            tracing::warn!("failed to parse upstream body: {err}");
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!("failed read upstream bytes stream: {err}")
                }
            }
        }
    }
}
