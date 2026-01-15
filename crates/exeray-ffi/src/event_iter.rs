//! Iterator over events in the EventGraph.

use crate::engine::Engine;
use crate::event::Event;

/// Iterator over events in the EventGraph.
pub struct EventIter<'a> {
    pub(crate) engine: &'a Engine,
    pub(crate) index: usize,
    pub(crate) count: usize,
}

impl<'a> Iterator for EventIter<'a> {
    type Item = Event;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        let event = self.engine.get_event(self.index);
        self.index += 1;
        event
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EventIter<'_> {}
