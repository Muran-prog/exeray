mod app;
mod ui;

use anyhow::Result;
use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;
use std::io::stdout;
use std::time::Duration;

fn main() -> Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;

    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let result = run(&mut terminal);

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    result
}

fn run<B: Backend>(terminal: &mut Terminal<B>) -> Result<()> {
    let mut app = app::App::new(64, 0);

    loop {
        terminal.draw(|f| ui::render(&app, f))?;

        if event::poll(Duration::from_millis(16))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char(' ') => app.start(),
                _ => {}
            }
        }

        app.tick();
    }

    Ok(())
}
