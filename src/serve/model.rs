use serde::{Deserialize, Deserializer, Serialize};
use typed_builder::TypedBuilder;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    Assistant,
    User,
}

// ==================== Request Body ====================
#[derive(Debug, Serialize, Deserialize)]
pub struct ChatRequest {
    #[serde(deserialize_with = "deserialize_model")]
    model: String,
    #[serde(deserialize_with = "deserialize_message")]
    messages: Vec<Message>,
    #[serde(skip_serializing, default)]
    stream: Option<bool>,
}

impl ChatRequest {
    pub fn stream(&self) -> Option<bool> {
        self.stream
    }
    pub fn model(self) -> String {
        self.model
    }
}

#[derive(Debug, Serialize, Deserialize, Default, TypedBuilder)]
pub struct Message {
    #[builder(default, setter(into))]
    role: Option<Role>,
    #[builder(default, setter(into))]
    content: Option<Content>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Content {
    Text(String),
    Vec(Vec<ContentItem>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContentItem {
    #[serde(rename = "type")]
    r#type: String,
    text: String,
}

fn deserialize_model<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let model = String::deserialize(deserializer)?;
    let model = match model.as_str() {
        "claude-3-haiku" => "claude-3-haiku-20240307",
        "llama-3.1-70b" => "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "mixtral-8x7b" => "mistralai/Mixtral-8x7B-Instruct-v0.1",
        "gpt-4o-mini" => "gpt-4o-mini",
        "o3-mini" => "o3-mini",
        _ => model.as_str(),
    };
    Ok(model.to_owned())
}

// fn deserialize_message<'de, D>(deserializer: D) -> Result<Vec<Message>, D::Error>
// where
//     D: Deserializer<'de>,
// {
//     let mut message: Vec<Message> = Vec::deserialize(deserializer)?;
//     for message in &mut message {
//         if let Some(role) = message.role.as_mut() {
//             if matches!(role, Role::System) {
//                 *role = Role::User;
//             }
//         }
//     }
//     Ok(message)
// }

fn deserialize_message<'de, D>(deserializer: D) -> Result<Vec<Message>, D::Error>
where
    D: Deserializer<'de>,
{
    let message: Vec<Message> = Vec::deserialize(deserializer)?;
    let mut compression_message = Vec::with_capacity(message.len());
    for mut message in message {
        if let (Some(role), Some(msg)) = (message.role.as_mut(), message.content) {
            if matches!(role, Role::System) {
                *role = Role::User;
            }

            let role_str = serde_json::to_string(&role).unwrap();
            match msg {
                Content::Text(msg) => {
                    compression_message.push(format!("{}:{};", role_str, msg))
                }
                Content::Vec(vec) => {
                    for item in vec {
                        compression_message.push(format!("{}:{};", role_str, item.text));
                    }
                }
            }
        }
    }

    Ok(vec![Message::builder()
        .role(Role::User)
        .content(Content::Text(compression_message.join("\n")))
        .build()])
}


// ==================== Duck APi Response Body ====================
#[derive(Deserialize)]
pub struct DuckChatCompletion {
    pub message: Option<String>,
    pub created: u64,
    #[serde(default = "default_id")]
    pub id: String,
    pub model: Option<String>,
}

fn default_id() -> String {
    "chatcmpl-123".to_owned()
}

// ==================== Response Body ====================
#[derive(Serialize, TypedBuilder)]
pub struct ChatCompletion<'a> {
    #[builder(default, setter(into))]
    #[serde(default = "default_id")]
    id: Option<String>,

    object: &'static str,

    #[builder(default, setter(into))]
    created: Option<u64>,

    model: &'a str,

    choices: Vec<Choice>,

    #[builder(default, setter(into))]
    usage: Option<Usage>,
}

#[derive(Serialize, TypedBuilder)]
pub struct Choice {
    index: usize,

    #[builder(default, setter(into))]
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<Message>,

    #[builder(default, setter(into))]
    #[serde(skip_serializing_if = "Option::is_none")]
    delta: Option<Message>,

    #[builder(setter(into))]
    logprobs: Option<String>,

    #[builder(setter(into))]
    finish_reason: Option<&'static str>,
}

#[derive(Serialize, TypedBuilder)]
pub struct Usage {
    prompt_tokens: i32,
    completion_tokens: i32,
    total_tokens: i32,
}
