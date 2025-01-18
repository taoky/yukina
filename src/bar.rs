use crate::BAR_MANAGER;

pub fn get_progress_bar(len: u64, message: &str, template: Option<&str>) -> kyuri::Bar {
    BAR_MANAGER.get().unwrap().create_bar(
        len,
        message,
        template.unwrap_or("{msg}: {bar} ({pos}/{len})"),
        true,
    )
}
