use std::{
    collections::BTreeMap,
    env,
    sync::{Condvar, Mutex, OnceLock, PoisonError, mpsc},
    thread,
};

const MAX_THREADS: usize = 16;

pub fn threads() -> usize {
    static THREADS: OnceLock<usize> = OnceLock::new();
    *THREADS.get_or_init(|| {
        env::var("ANDROID_RESIGNER_THREADS").ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|&count| count > 0)
            .unwrap_or_else(|| thread::available_parallelism().map_or(1, |count| count.get()))
            .min(MAX_THREADS)
    })
}

struct Gate { next: usize, limit: usize, stop: bool }

pub fn ordered<T, E, F, C>(count: usize, task: F, mut consume: C) -> Result<(), E>
where
    T: Send,
    E: Send,
    F: Fn(usize) -> Result<T, E> + Sync,
    C: FnMut(T) -> Result<(), E>,
{
    let workers = threads().min(count);
    if workers <= 1 {
        for index in 0..count { consume(task(index)?)?; }
        return Ok(())
    }
    let window = workers * 2;
    let gate = Mutex::new(Gate { next: 0, limit: window.min(count), stop: false });
    let wake = Condvar::new();
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..workers {
            let (sender, gate, wake, task) = (sender.clone(), &gate, &wake, &task);
            scope.spawn(move || loop {
                let index = {
                    let mut state = gate.lock().unwrap_or_else(PoisonError::into_inner);
                    while !state.stop && state.next < count && state.next >= state.limit {
                        state = wake.wait(state).unwrap_or_else(PoisonError::into_inner);
                    }
                    if state.stop || state.next >= count { return }
                    state.next += 1;
                    state.next - 1
                };
                let result = task(index);
                let failed = result.is_err();
                if sender.send((index, result)).is_err() || failed { return }
            });
        }
        drop(sender);
        let mut early = BTreeMap::new();
        let mut result = Ok(());
        for expected in 0..count {
            let item = match early.remove(&expected) {
                Some(item) => item,
                None => loop {
                    let (index, item) = receiver.recv().expect("parallel worker exited before sending its result");
                    if index == expected { break item }
                    early.insert(index, item);
                },
            };
            gate.lock().unwrap_or_else(PoisonError::into_inner).limit = (expected + 1 + window).min(count);
            wake.notify_all();
            if let Err(error) = item.and_then(&mut consume) { result = Err(error); break }
        }
        gate.lock().unwrap_or_else(PoisonError::into_inner).stop = true;
        wake.notify_all();
        result
    })
}

pub fn for_each<T, E, F>(items: Vec<T>, task: F) -> Result<(), E>
where
    T: Send,
    E: Send,
    F: Fn(T) -> Result<(), E> + Sync,
{
    let slots = items.into_iter().map(|item| Mutex::new(Some(item))).collect::<Vec<_>>();
    ordered(slots.len(), |index| {
        task(slots[index].lock().unwrap_or_else(PoisonError::into_inner).take().expect("parallel item taken twice"))
    }, |()| Ok(()))
}
