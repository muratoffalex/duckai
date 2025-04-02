use crate::Result;
use crate::error::Error::{self, HashError, MissingHeader};
use crate::model::ChatRequest;
use crate::serve::AppState;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use axum_extra::{
    TypedHeader,
    extract::WithRejection,
    headers::{Authorization, authorization::Bearer},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use process::ChatProcess;
use regex::Regex;
use reqwest::{Client, header};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const ORIGIN_API: &str = "https://duckduckgo.com";

pub async fn models(
    State(state): State<AppState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> crate::Result<Response> {
    state.valid_key(bearer)?;

    let model_data = vec![
        serde_json::json!({
            "id": "gpt-4o-mini",
            "object": "model",
            "created": 1686935002,
            "owned_by": "openai",
        }),
        serde_json::json!({
            "id": "claude-3-haiku",
            "object": "model",
            "created": 1686935002,
            "owned_by": "claude",
        }),
        serde_json::json!({
            "id": "llama-3.3-70b",
            "object": "model",
            "created": 1686935002,
            "owned_by": "meta-llama",
        }),
        serde_json::json!({
            "id": "o3-mini",
            "object": "model",
            "created": 1686935002,
            "owned_by": "openai",
        }),
        serde_json::json!({
            "id": "mixtral-small-3",
            "object": "model",
            "created": 1686935002,
            "owned_by": "mistral ai",
        }),
    ];

    Ok(Json(serde_json::json!({
        "object": "list",
        "data": model_data,
    }))
    .into_response())
}

pub async fn chat_completions(
    State(state): State<AppState>,
    bearer: Option<TypedHeader<Authorization<Bearer>>>,
    WithRejection(Json(mut body), _): WithRejection<Json<ChatRequest>, Error>,
) -> crate::Result<Response> {
    state.valid_key(bearer)?;
    let token = {
        let token = load_token(&state.client).await?;
        body.compress_messages();
        token
    };
    let (_, response) = send_request(&state.client, token, &body).await?;
    Ok(response)
}

async fn send_request(
    client: &Client,
    (token, hash): (String, String),
    body: &ChatRequest,
) -> Result<((String, String), Response)> {
    let mut request_hash;
    // FIXME
    loop {
        request_hash = gen_request_hash(&hash);
        if request_hash.is_ok() {
            break;
        }
    }

    let resp = client
        .post("https://duckduckgo.com/duckchat/v1/chat")
        .header(header::ACCEPT, "text/event-stream")
        .header(header::ORIGIN, ORIGIN_API)
        .header(header::REFERER, ORIGIN_API)
        .header("x-vqd-4", token)
        .header("x-vqd-hash-1", request_hash?)
        .json(&body)
        .send()
        .await?;

    let token = resp
        .headers()
        .get("x-vqd-4")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| MissingHeader)?
        .to_owned();

    let hash = resp
        .headers()
        .get("x-vqd-hash-1")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| MissingHeader)?
        .to_owned();

    let response = ChatProcess::builder()
        .resp(resp)
        .stream(body.stream)
        .model(body.model.clone())
        .build()
        .into_response()
        .await?;

    Ok(((token, hash), response))
}

async fn load_token(client: &Client) -> Result<(String, String)> {
    let resp = client
        .get("https://duckduckgo.com/duckchat/v1/status")
        .header(header::REFERER, ORIGIN_API)
        .header("x-vqd-accept", "1")
        .send()
        .await?
        .error_for_status()?;

    let token = resp
        .headers()
        .get("x-vqd-4")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| crate::Error::MissingHeader)?
        .to_owned();

    let hash = resp
        .headers()
        .get("x-vqd-hash-1")
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| crate::Error::MissingHeader)?
        .to_owned();

    Ok((token, hash))
}

fn gen_request_hash(hash: &str) -> Result<String> {
    let decoded_bytes = BASE64_STANDARD
        .decode(hash.as_bytes())
        .expect("invalid base64");
    let decoded_str = String::from_utf8(decoded_bytes).expect("invalid utf-8");

    let string_array: Vec<&str> = Regex::new(r"=\[([^\]]*)\]")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| cap.get(1))
        .ok_or_else(|| HashError("string array not found"))?
        .as_str()
        .split(',')
        .map(|s| s.trim_matches('\''))
        .collect();

    let offset: i32 = Regex::new(r"0x([[:alnum:]]+);let")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| cap.get(1))
        .and_then(|s| i32::from_str_radix(s.as_str(), 16).ok())
        .ok_or_else(|| HashError("offset not found"))?;
    // dbg!(&decoded_str);

    let server_hash_indices: (i32, i32) =
        Regex::new(r"'server_hashes':\[_0x[[:alnum:]]+\(0x([[:alnum:]]+)\),_0x[[:alnum:]]+\(0x([[:alnum:]]+)\)\]")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| cap.get(1).zip(cap.get(2)))
        .and_then(|(s1, s2)| i32::from_str_radix(s1.as_str(), 16).ok().zip(i32::from_str_radix(s2.as_str(), 16).ok()))
        .ok_or_else(|| HashError("server hash indices not found"))?;
    // dbg!(server_hash_indices);

    let user_agent_index: i32 =
        Regex::new(r"'client_hashes':\[navigator\[_0x[[:alnum:]]+\(0x([[:alnum:]]+)\)\]")
            .unwrap()
            .captures(&decoded_str)
            .and_then(|cap| cap.get(1))
            .and_then(|s| i32::from_str_radix(s.as_str(), 16).ok())
            .ok_or_else(|| HashError("user agent indices not found"))?;
    // dbg!(user_agent_index);

    let origin_user_agent_index: i32 = string_array
        .iter()
        .position(|&s| s == "userAgent")
        .ok_or_else(|| HashError("origin user agent index not found"))?
        as i32;
    // dbg!(origin_user_agent_index);

    let origin_server_hash_indices = (
        (server_hash_indices.0 - offset + string_array.len() as i32 + origin_user_agent_index
            - (user_agent_index - offset))
            % (string_array.len() as i32),
        (server_hash_indices.1 - offset + string_array.len() as i32 + origin_user_agent_index
            - (user_agent_index - offset))
            % (string_array.len() as i32),
    );
    // dbg!(origin_server_hash_indices);

    let server_hashes = [
        string_array[origin_server_hash_indices.0 as usize],
        string_array[origin_server_hash_indices.1 as usize],
    ];
    // dbg!(server_hashes);

    let innerhtml_index = Regex::new(r"\(0x([[:alnum:]]+)\),String")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| cap.get(1))
        .and_then(|s| i32::from_str_radix(s.as_str(), 16).ok())
        .ok_or_else(|| HashError("user agent indices not found"))?;
    // dbg!(innerhtml_index);

    let origin_innerhtml_index =
        (innerhtml_index - offset + string_array.len() as i32 + origin_user_agent_index
            - (user_agent_index - offset))
            % (string_array.len() as i32);
    // dbg!(origin_innerhtml_index);

    let innerhtml = string_array[origin_innerhtml_index as usize];
    // dbg!(innerhtml);

    let inner_html_data: HashMap<&str, i32> = HashMap::from([
        ("<div><div></div><div></div", 99),
        ("<p><div></p><p></div", 128),
        ("<br><div></br><br></div", 92),
        ("<li><div></li><li></div", 87),
    ]);

    let inner_html_len = inner_html_data
        .get(innerhtml)
        .expect(&format!("new pattern {}", &innerhtml));

    let extracted_number: i32 = Regex::new(r"String\(0x([[:alnum:]]+)\+")
        .unwrap()
        .captures(&decoded_str)
        .and_then(|cap| cap.get(1))
        .and_then(|s| i32::from_str_radix(s.as_str(), 16).ok())
        .ok_or_else(|| HashError("extracted number not found"))?;
    // dbg!(extracted_number);

    fn compute_sha256_base64(input: &str) -> String {
        let hash = Sha256::digest(input.as_bytes());
        BASE64_STANDARD.encode(hash)
    }

    let user_agent_hash = compute_sha256_base64(crate::client::USER_AGENT);
    let number_hash = compute_sha256_base64(&(extracted_number + inner_html_len).to_string());

    let result_json = serde_json::json!({
        "server_hashes": server_hashes,
        "client_hashes": [user_agent_hash, number_hash],
        "signals": {}
    });
    Ok(BASE64_STANDARD.encode(result_json.to_string()))
}

mod process {

    use crate::model::{ChatCompletion, Choice, Content, DuckChatCompletion, Message, Role, Usage};
    use axum::{
        Error, Json,
        response::{IntoResponse, Response, Sse, sse::Event},
    };
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
                let bad_data = self.resp.text().await?;
                return Err(crate::Error::BadRequest(bad_data));
            }

            let raw_model = self.model;

            if self.stream.unwrap_or_default() {
                let mut first_message = true;
                let sse_stream = process_stream_with_chunk(
                    self.resp,
                    move |body| {
                        if let Some(content) = body.message {
                            let role = if first_message {
                                first_message = false;
                                Some(Role::Assistant)
                            } else {
                                None
                            };

                            let chat_completion = ChatCompletion::builder()
                                .id(body.id)
                                .model(&raw_model)
                                .object("chat.completion.chunk")
                                .created(body.created)
                                .choices(vec![
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
                                        .build(),
                                ])
                                .build();

                            return Event::default()
                                .json_data(chat_completion)
                                .map_err(Error::new);
                        }

                        let chat_completion = ChatCompletion::builder()
                            .id(body.id)
                            .model(&raw_model)
                            .object("chat.completion.chunk")
                            .created(body.created)
                            .choices(vec![
                                Choice::builder()
                                    .index(0)
                                    .delta(Message::default())
                                    .logprobs(None)
                                    .finish_reason("stop")
                                    .build(),
                            ])
                            .build();

                        // if let Some(ref model) = body.model {
                        //     tracing::info!("model mapper: {} -> {}", raw_model, model);
                        // }

                        Event::default()
                            .json_data(chat_completion)
                            .map_err(Error::new)
                    },
                    |event| Ok(Event::default().data(event.data)),
                );
                return Ok(Sse::new(sse_stream).into_response());
            }

            let mut id = None;
            let mut created = None;
            let mut model = None;
            let mut content = String::new();
            process_stream(self.resp, |body| {
                // Update id
                if id.is_none() {
                    id = Some(body.id);
                }

                // Update created time
                if created.is_none() {
                    created = Some(body.created);
                }

                // Update model
                if model.is_none() {
                    model = Some(body.model);
                }

                // Append chat message
                if let Some(message) = body.message {
                    content.push_str(&message);
                }
            })
            .await;

            // if let Some(Some(model)) = model {
            //     tracing::info!("model mapper: {} -> {}", raw_model, model);
            // }

            let chat_completion = ChatCompletion::builder()
                .id(id)
                .model(&raw_model)
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
                    if event.data.eq("[DONE]") {
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
                        if event.data.eq("[DONE]") {
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
}
