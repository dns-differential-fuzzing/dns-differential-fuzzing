use color_eyre::eyre::Result;
use futures::Future;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

/// Create a [`String`] with random content of specified length
///
/// The [`String`] will contain alphanumeric ASCII characters.
pub(crate) fn rand_string(length: usize) -> String {
    use rand::seq::SliceRandom;

    let mut s = String::with_capacity(length);
    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for _ in 0..length {
        s.push(
            *chars
                .choose(&mut rand::thread_rng())
                .expect("Non-empty array shouldn't fail") as char,
        );
    }
    s
}

pub(crate) trait JoinSetExt<T> {
    #[track_caller]
    fn spawn_named<F>(&mut self, name: &str, task: F) -> AbortHandle
    where
        F: Future<Output = T>,
        F: Send + 'static,
        T: Send;
}

impl<T: 'static> JoinSetExt<T> for JoinSet<T> {
    #[track_caller]
    fn spawn_named<F>(&mut self, name: &str, task: F) -> AbortHandle
    where
        F: Future<Output = T>,
        F: Send + 'static,
        T: Send,
    {
        #[cfg(not(tokio_unstable))]
        {
            let _ = name;
            self.spawn(task)
        }
        #[cfg(tokio_unstable)]
        {
            self.build_task()
                .name(name)
                .spawn(task)
                .expect("Failed to spawn task on JoinSet")
        }
    }
}

#[track_caller]
pub(crate) fn task_spawn_named<T>(name: &str, future: T) -> JoinHandle<T::Output>
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
{
    #[cfg(not(tokio_unstable))]
    {
        let _ = name;
        tokio::task::spawn(future)
    }
    #[cfg(tokio_unstable)]
    {
        tokio::task::Builder::new()
            .name(name)
            .spawn(future)
            .expect("Failed to spawn global task")
    }
}

// /// Necessary to work around some compiler limitations
// ///
// /// https://github.com/rust-lang/rust/issues/102211
// pub(crate) fn assert_send<'u, R>(
//     fut: impl 'u + Send + Future<Output = R>,
// ) -> impl 'u + Send + Future<Output = R> {
//     fut
// }

/// Necessary to work around some compiler limitations
///
/// https://github.com/rust-lang/rust/issues/102211
pub(crate) fn stream_assert_send<'a, T>(
    stream: impl futures::Stream<Item = T> + Send + 'a,
) -> impl futures::Stream<Item = T> + Send + 'a {
    stream
}

pub(crate) fn ok<T>(t: T) -> Result<T> {
    Ok(t)
}
