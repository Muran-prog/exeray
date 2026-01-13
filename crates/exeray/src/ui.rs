use crate::app::App;
use exeray_ffi::ViewState;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Paragraph},
};

pub fn render(app: &App, frame: &mut Frame) {
    let layout = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .margin(2)
    .split(frame.area());

    header(app, frame, layout[0]);
    progress(app.state(), frame, layout[1]);
    status(app.state(), frame, layout[2]);
    help(frame, layout[3]);
}

fn header(app: &App, frame: &mut Frame, area: Rect) {
    let text = format!(
        "ExeRay │ Gen: {} │ Threads: {}",
        app.state().generation,
        app.threads()
    );

    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Engine"))
            .style(Style::default().fg(Color::Cyan)),
        area,
    );
}

fn progress(state: &ViewState, frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Progress"))
            .gauge_style(Style::default().fg(Color::Green))
            .percent((state.progress * 100.0).min(100.0) as u16),
        area,
    );
}

fn status(state: &ViewState, frame: &mut Frame, area: Rect) {
    let (text, color) = if state.is_complete() {
        ("Complete", Color::Green)
    } else if state.is_pending() {
        ("Running", Color::Yellow)
    } else {
        ("Idle", Color::DarkGray)
    };

    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Status"))
            .style(Style::default().fg(color)),
        area,
    );
}

fn help(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new("Space: Start │ Q: Quit").style(Style::default().fg(Color::DarkGray)),
        area,
    );
}
