use chrono::Utc;
fn main() {
    let now = Utc::now().to_rfc3339();
    println!("{}", now);
}
