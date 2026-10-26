use std::collections::HashMap;

pub trait Fetch {
    async fn fetch(&self, id: u32) -> Option<String>;
    type Item<'a>: 'a where Self: 'a;
}

pub struct Client {
    cache: HashMap<u32, String>,
}

impl Fetch for Client {
    type Item<'a> = &'a str;
    async fn fetch(&self, id: u32) -> Option<String> {
        let Some(v) = self.cache.get(&id) else {
            return None;
        };
        Some(v.clone())
    }
}

impl Client {
    pub fn new() -> Self {
        Self { cache: HashMap::new() }
    }
    pub fn check(&self, id: u32) -> bool {
        if let Some(v) = self.cache.get(&id)
            && v.len() > 2
        {
            return self.helper(v);
        }
        false
    }
    fn helper(&self, v: &str) -> bool {
        !v.is_empty()
    }
}

pub fn apply(f: impl Fn(u32) -> u32, x: u32) -> u32 {
    f(x)
}

pub fn main() {
    let c = Client::new();
    c.check(1);
    apply(|x| x + 1, 2);
}
