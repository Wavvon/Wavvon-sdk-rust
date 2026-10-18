use std::collections::VecDeque;
use std::future::Future;

use futures::stream::{self, BoxStream, StreamExt};

use crate::error::{Error, Result};

struct State<T, K, F> {
    buf: VecDeque<T>,
    cursor: Option<String>,
    more: bool,
    failure: Option<Error>,
    key: K,
    fetch: F,
}

/// Walks a keyset-paged list to exhaustion. `fetch(cursor, limit)` returns one
/// page; `key` names a row's cursor (the hub pages by the last row's key).
///
/// A page shorter than `limit` ends the walk. An error from `fetch` is
/// yielded and ends it, so a transient failure is never taken for the end of
/// the list. A hub that ignores the cursor (and so repeats a full page) is an
/// error, not an endless loop; rows already fetched are delivered first.
pub fn pager<T, K, F, Fut>(limit: u64, key: K, fetch: F) -> BoxStream<'static, Result<T>>
where
    T: Send + 'static,
    K: Fn(&T) -> Option<String> + Send + 'static,
    F: FnMut(Option<String>, u64) -> Fut + Send + 'static,
    Fut: Future<Output = Result<Vec<T>>> + Send + 'static,
{
    let state = State {
        buf: VecDeque::new(),
        cursor: None,
        more: true,
        failure: None,
        key,
        fetch,
    };
    stream::unfold(state, move |mut s| async move {
        loop {
            if let Some(item) = s.buf.pop_front() {
                return Some((Ok(item), s));
            }
            if let Some(e) = s.failure.take() {
                return Some((Err(e), s));
            }
            if !s.more {
                return None;
            }
            let page = match (s.fetch)(s.cursor.clone(), limit).await {
                Ok(p) => p,
                Err(e) => {
                    s.more = false;
                    return Some((Err(e), s));
                }
            };
            let full = page.len() as u64 >= limit;
            let next = page.last().map(|last| (s.key)(last));
            s.more = full;
            if full {
                match next {
                    Some(Some(k)) if Some(&k) != s.cursor.as_ref() => s.cursor = Some(k),
                    Some(Some(_)) => {
                        s.more = false;
                        s.failure = Some(Error::Decode(
                            "full page repeated for the same cursor: the hub ignores `cursor`"
                                .into(),
                        ));
                    }
                    _ => {
                        s.more = false;
                        s.failure = Some(Error::Decode("a row has no key to page by".into()));
                    }
                }
            }
            s.buf.extend(page);
        }
    })
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(
        rows: usize,
    ) -> impl FnMut(Option<String>, u64) -> std::future::Ready<Result<Vec<usize>>> {
        move |cursor, limit| {
            let start = cursor.map_or(0, |c| c.parse::<usize>().unwrap() + 1);
            let end = (start + limit as usize).min(rows);
            std::future::ready(Ok((start..end).collect()))
        }
    }

    async fn collect(rows: usize, limit: u64) -> Vec<usize> {
        let s = pager(limit, |r: &usize| Some(r.to_string()), fake(rows));
        s.map(|r| r.unwrap()).collect().await
    }

    #[tokio::test]
    async fn walks_every_page_including_a_short_last_one() {
        assert_eq!(collect(1050, 500).await.len(), 1050);
        assert_eq!(collect(7, 3).await, (0..7).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn exact_multiple_ends_on_the_empty_page() {
        assert_eq!(collect(1000, 500).await.len(), 1000);
        assert!(collect(0, 500).await.is_empty());
    }

    #[tokio::test]
    async fn an_error_is_yielded_not_read_as_the_end() {
        let mut calls = 0;
        let s = pager(
            2,
            |r: &usize| Some(r.to_string()),
            move |_, _| {
                calls += 1;
                std::future::ready(if calls == 1 {
                    Ok(vec![1usize, 2])
                } else {
                    Err(Error::Transient {
                        attempts: 6,
                        last: "503".into(),
                    })
                })
            },
        );
        let items: Vec<_> = s.collect().await;
        assert_eq!(items.len(), 3);
        assert!(items[0].is_ok() && items[1].is_ok());
        assert!(matches!(items[2], Err(Error::Transient { .. })));
    }

    #[tokio::test]
    async fn a_hub_that_ignores_the_cursor_is_an_error() {
        let s = pager(
            2,
            |r: &usize| Some(r.to_string()),
            |_, _| std::future::ready(Ok(vec![1usize, 2])),
        );
        let items: Vec<_> = s.collect().await;
        assert!(matches!(items.last(), Some(Err(Error::Decode(_)))));
        assert!(items.len() <= 5);
    }
}
