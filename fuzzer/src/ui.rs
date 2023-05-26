use crate::stats::OracleStats;
use crate::{ok, SHOULD_TERMINATE};
use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{cursor, execute};
use futures::{FutureExt as _, StreamExt as _};
use std::fmt::Formatter;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tui::backend::{Backend, CrosstermBackend};
use tui::layout::{Constraint, Direction, Layout, Rect};
use tui::style::{Color, Modifier, Style};
use tui::text::Span;
use tui::widgets::{Block, Borders, Cell, List, ListItem, ListState, Row, Table, TableState};
use tui::{Frame, Terminal};

pub(crate) struct App {
    statistics: Arc<Mutex<crate::stats::FuzzingStats>>,
    executor_list_state: ListState,
    executor_table_state: TableState,
    differences_list_state: ListState,
    differences_table_state: TableState,
}

impl App {
    pub(crate) async fn run(statistics: Arc<Mutex<crate::stats::FuzzingStats>>) -> Result<()> {
        let (mut terminal, _terminal_guard) = tokio::task::block_in_place(|| {
            // setup terminal
            let terminal_guard = TerminalGuard::new()?;
            let backend = CrosstermBackend::new(io::stdout());
            let terminal = Terminal::new(backend)?;

            let hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |f| {
                let mut stdout = io::stdout();
                let _ = execute!(stdout, LeaveAlternateScreen, cursor::Show);
                let _ = disable_raw_mode();
                hook(f);
            }));

            ok((terminal, terminal_guard))
        })?;

        let mut app = App {
            statistics,
            executor_list_state: {
                let mut ls = ListState::default();
                ls.select(Some(0));
                ls
            },
            executor_table_state: {
                let mut ts = TableState::default();
                ts.select(Some(0));
                ts
            },
            differences_list_state: {
                let mut ls = ListState::default();
                ls.select(Some(0));
                ls
            },
            differences_table_state: {
                let mut ts = TableState::default();
                ts.select(Some(0));
                ts
            },
        };

        let tick_rate = Duration::from_millis(200);
        let mut interval = tokio::time::interval(tick_rate);
        let mut events = EventStream::new();
        loop {
            let stats_has_timeline;
            {
                let stats = app.statistics.clone();
                let stats = stats.lock().await;
                stats_has_timeline = stats.timeline.is_some();
                tokio::task::block_in_place(|| terminal.draw(|f| app.draw(f, &stats)))?;
            }
            let event = events.next().fuse();
            tokio::select! {
                _ = interval.tick() => {},
                maybe_event = event => {
                    match maybe_event {
                        None => break,
                        Some(Ok(Event::Key(key))) => {
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Char('c')
                                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    SHOULD_TERMINATE.store(true, Ordering::SeqCst);
                                }
                                KeyCode::Left if stats_has_timeline=> {
                                    // Move to an earlier timepoint if possible
                                    let mut stats = app.statistics.lock().await;
                                    if let Some((files, idx)) = &stats.timeline {
                                        if *idx > 0 {
                                            let stats_new = tokio::task::block_in_place(|| crate::stats::FuzzingStats::from_timeline(files.clone(), idx-1))?;
                                            *stats = stats_new;
                                        }
                                    }
                                }
                                KeyCode::Right if stats_has_timeline=> {
                                    // Move to a later timepoint if possible
                                    let mut stats = app.statistics.lock().await;
                                    if let Some((files, idx)) = &stats.timeline {
                                        if *idx < files.len() - 1 {
                                            let stats_new = tokio::task::block_in_place(|| crate::stats::FuzzingStats::from_timeline(files.clone(), idx+1))?;
                                            *stats = stats_new;
                                        }
                                    }}
                                KeyCode::Up => {
                                    let stats = app.statistics.lock().await;
                                    let stats = &*stats;
                                    let selected = app.executor_list_state.selected().unwrap_or(0);
                                    app.executor_list_state.select(Some(
                                        selected.checked_sub(1).unwrap_or(stats.coverage.len().saturating_sub(1)),
                                    ));
                                    let selected = app.differences_list_state.selected().unwrap_or(0);
                                    app.differences_list_state.select(Some(
                                        selected
                                            .checked_sub(1)
                                            .unwrap_or(stats.differences.len().saturating_sub(1)),
                                    ));
                                }
                                KeyCode::Down => {
                                    let stats = app.statistics.lock().await;
                                    let stats = &*stats;
                                    let selected = app.executor_list_state.selected().unwrap_or(0);
                                    app.executor_list_state.select(Some(
                                        if selected + 1 == stats.coverage.len() {
                                            0
                                        } else {
                                            selected + 1
                                        },
                                    ));
                                    let selected = app.differences_list_state.selected().unwrap_or(0);
                                    app.differences_list_state.select(Some(
                                        if selected + 1 == stats.differences.len() {
                                            0
                                        } else {
                                            selected + 1
                                        },
                                    ));
                                }
                                _ => {}
                            }
                        }

                        Some(Ok(_)) => {}
                        Some(Err(e)) => {
                            Err(e)?;
                        }
                    }
                }
            }
            if SHOULD_TERMINATE.load(Ordering::SeqCst) {
                break;
            }
        }
        Ok(())
    }

    fn draw<B: Backend>(&mut self, f: &mut Frame<'_, B>, stats: &crate::FuzzingStats) {
        // TODO add a status line, like showing the commands or that the program is exiting
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(
                [
                    Constraint::Length(5),
                    Constraint::Length(10),
                    Constraint::Min(10),
                    Constraint::Length(15),
                ]
                .as_ref(),
            )
            .split(f.size());

        let elapsed = stats.start_time.elapsed();

        self.draw_basic(f, chunks[0], stats, elapsed);
        self.draw_executor_stats(f, chunks[1], stats, elapsed);
        self.draw_differences_stats(f, chunks[2], stats);
        f.render_widget(
            tui_logger::TuiLoggerWidget::default()
                .block(
                    Block::default()
                        .title(Span::styled(
                            "Log",
                            Style::default().add_modifier(Modifier::BOLD),
                        ))
                        .borders(Borders::LEFT | Borders::TOP)
                        .border_style(Style::default().add_modifier(Modifier::DIM)),
                )
                .style_error(Style::default().fg(Color::Red))
                .style_debug(Style::default().fg(Color::Green))
                .style_warn(Style::default().fg(Color::Yellow))
                .style_trace(Style::default().fg(Color::Magenta))
                .style_info(Style::default().fg(Color::Cyan))
                .output_timestamp(Some("%F %T%.3f".to_string())),
            chunks[3],
        );
    }

    fn draw_basic<B: Backend>(
        &mut self,
        f: &mut Frame<'_, B>,
        rect: Rect,
        stats: &crate::FuzzingStats,
        elapsed: Duration,
    ) {
        // Frame the whole area in a block
        let block = Block::default()
            .title(Span::styled(
                "Basic Stats",
                Style::default().add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::LEFT | Borders::TOP)
            .border_style(Style::default().add_modifier(Modifier::DIM));
        let new_rect = block.inner(rect);
        f.render_widget(block, rect);
        let rect = new_rect;

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(34), Constraint::Length(40)].as_ref())
            .split(rect);

        // Basic stats
        let num_width = (stats.fuzz_case_count as f64).log10().ceil() as usize;
        let rows = [
            Row::new([
                Cell::from("Runtime"),
                Cell::from(FormattedDuration(elapsed).to_string()),
            ]),
            Row::new([
                Cell::from("Fuzz Cases"),
                App::num_cell(
                    stats.fuzz_case_count,
                    stats.fuzz_case_count,
                    num_width,
                    Some(elapsed.as_secs()),
                ),
            ])
            .height(2),
            Row::new([
                Cell::from("Fingerprints"),
                App::num_cell(stats.fingerprints, None, num_width, None),
            ]),
        ];
        let tbl = Table::new(rows)
            // Columns widths are constrained in the same way as Layout...
            .widths(&[Constraint::Length(13), Constraint::Min(20)])
            .column_spacing(1);
        f.render_widget(tbl, chunks[0]);

        // Show values about the population pool
        let num_width = (stats.population_size as f64).log10().ceil() as usize;

        let rows = 3;
        let mut entries_per_row = stats.top_n_priorities.len() / rows;
        if entries_per_row % rows != 0 {
            // If the number of entries per row is not divisible by the number of rows, we need to
            // add one to the number of rows to make sure we don't miss any entries
            entries_per_row += 1;
        }
        let mut priorities = stats.top_n_priorities.iter().take(9);
        let mut formatted_priorities = String::new();
        for _ in 0..rows {
            for _ in 0..entries_per_row {
                if let Some(priority) = priorities.next() {
                    formatted_priorities.push_str(&format!("{:.1}, ", priority,));
                }
            }
            formatted_priorities.push('\n');
        }
        let rows = [
            Row::new([
                Cell::from("Population"),
                App::num_cell(
                    stats.population_size,
                    stats.fuzz_case_count,
                    num_width,
                    None,
                ),
            ]),
            Row::new([
                Cell::from("Top Priorities"),
                Cell::from(formatted_priorities),
            ])
            .height(3),
        ];
        let tbl = Table::new(rows)
            // Columns widths are constrained in the same way as Layout...
            .widths(&[Constraint::Length(16), Constraint::Min(20)])
            .column_spacing(1);
        f.render_widget(tbl, chunks[1]);
    }

    fn draw_executor_stats<B: Backend>(
        &mut self,
        f: &mut Frame<'_, B>,
        rect: Rect,
        stats: &crate::FuzzingStats,
        elapsed: Duration,
    ) {
        // Frame the whole area in a block
        let block = Block::default()
            .title(Span::styled(
                "Executor Stats",
                Style::default().add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::LEFT | Borders::TOP)
            .border_style(Style::default().add_modifier(Modifier::DIM));
        let new_rect = block.inner(rect);
        f.render_widget(block, rect);
        let rect = new_rect;

        // Split the area into two columns
        // Left with a list of executors
        // Right with a table of stats

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Length(25),
                    Constraint::Length(47),
                    Constraint::Length(52),
                    Constraint::Length(52),
                ]
                .as_ref(),
            )
            .split(rect);

        // Executor list
        let items: Vec<_> = stats
            .coverage
            .keys()
            .map(|k| ListItem::new(k.as_ref()))
            .collect();
        let list = List::new(items).highlight_symbol(">").block(
            Block::default()
                .borders(Borders::RIGHT)
                .border_style(Style::default().add_modifier(Modifier::DIM)),
        );
        f.render_stateful_widget(list, chunks[0], &mut self.executor_list_state);

        // Coverage stats
        let coverage_stats = stats
            .coverage
            .values()
            .nth(self.executor_list_state.selected().unwrap_or(0))
            .unwrap();
        let edges_total = coverage_stats.edges;
        let edges_num_width = (edges_total as f64).log10().ceil() as usize;
        let cases_total = stats.fuzz_case_count;
        let cases_num_width = (cases_total as f64).log10().ceil() as usize;
        let width = std::cmp::max(edges_num_width, cases_num_width);

        let rows = [
            ("Edges", coverage_stats.edges, edges_total),
            ("Explored", coverage_stats.explored_edges, edges_total),
            (
                "Progress Cases",
                coverage_stats.progress_fuzz_case_count,
                cases_total,
            ),
        ]
        .map(|(name, count, total)| {
            Row::new([Cell::from(name), App::num_cell(count, total, width, None)])
        });
        let tbl = Table::new(rows)
            // Columns widths are constrained in the same way as Layout...
            .widths(&[Constraint::Length(25), Constraint::Min(20)])
            .header(
                Row::new(vec!["Kind", "Count"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1);
        f.render_stateful_widget(tbl, chunks[1], &mut self.executor_table_state);

        // Executor stats
        let executor_stats = stats
            .executor
            .values()
            .nth(self.executor_list_state.selected().unwrap_or(0))
            .unwrap();

        let spawned_total = stats.fuzz_case_count;
        // There are multiple data source with different max values.
        // Account for all of them in the width calculation.
        let spawned_width = std::cmp::max(
            (spawned_total as f64).log10().ceil() as usize,
            (executor_stats.spawn_timeout.as_millis() as f64)
                .log10()
                .ceil() as usize,
        );

        let rows = [
            (
                "Queue Cap",
                executor_stats.queue_capacity,
                Some(executor_stats.queue_capacity),
                None,
            ),
            (
                "Queue Len",
                executor_stats.queue_len,
                Some(executor_stats.queue_capacity),
                None,
            ),
            (
                "Total Spawned",
                executor_stats.total_spawned,
                Some(spawned_total),
                Some(elapsed.as_secs()),
            ),
            (
                "Total Errors",
                executor_stats.total_errors,
                Some(spawned_total),
                Some(elapsed.as_secs()),
            ),
            ("Curr Errors", executor_stats.curr_errors, None, None),
        ]
        .map(|(name, count, total, time)| {
            Row::new([
                Cell::from(name),
                App::num_cell(count, total, spawned_width, time),
            ])
        })
        .into_iter()
        .chain(vec![Row::new([
            Cell::from("Spawn Time (ms)"),
            App::num_cell(
                executor_stats.spawn_timeout.as_millis() as u64,
                None,
                spawned_width,
                None,
            ),
        ])]);
        let tbl = Table::new(rows)
            // Columns widths are constrained in the same way as Layout...
            .widths(&[Constraint::Length(25), Constraint::Min(20)])
            .header(
                Row::new(vec!["Kind", "Count"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1);
        f.render_stateful_widget(tbl, chunks[2], &mut self.executor_table_state);

        // Oracle stats
        let oracle_stats = stats
            .oracles
            .values()
            .nth(self.executor_list_state.selected().unwrap_or(0))
            .unwrap();

        let spawned_total = stats.fuzz_case_count;
        let spawned_width = (spawned_total as f64).log10().ceil() as usize;

        let OracleStats {
            crashed_resolver_count,
            excessive_queries_count,
            excessive_answer_records_count,
            duplicate_records_count,
            fake_data_count,
            responds_to_response_count,
        } = *oracle_stats;
        let rows = [
            ("Crashes", crashed_resolver_count),
            ("Excessive Queries", excessive_queries_count),
            ("Excessive Answers", excessive_answer_records_count),
            ("Duplicate Records", duplicate_records_count),
            ("Fake Data", fake_data_count),
            ("Response QR=1", responds_to_response_count),
        ]
        .map(|(name, count)| {
            Row::new([
                Cell::from(name),
                App::num_cell(count, Some(spawned_total), spawned_width, None),
            ])
        });
        let tbl = Table::new(rows)
            // Columns widths are constrained in the same way as Layout...
            .widths(&[Constraint::Length(25), Constraint::Min(20)])
            .header(
                Row::new(vec!["Oracle", "Count"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1);
        f.render_stateful_widget(tbl, chunks[3], &mut self.executor_table_state);
    }

    fn draw_differences_stats<B: Backend>(
        &mut self,
        f: &mut Frame<'_, B>,
        rect: Rect,
        stats: &crate::FuzzingStats,
    ) {
        // Frame the whole area in a block
        let block = Block::default()
            .title(Span::styled(
                "Differences Stats",
                Style::default().add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::LEFT | Borders::TOP)
            .border_style(Style::default().add_modifier(Modifier::DIM));
        let new_rect = block.inner(rect);
        f.render_widget(block, rect);
        let rect = new_rect;

        // Split the area into two columns
        // Left with a list of executor pairs
        // Right with a table of stats

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Length(25),
                    Constraint::Length(47),
                    Constraint::Length(52),
                    Constraint::Length(52),
                ]
                .as_ref(),
            )
            .split(rect);

        // executor pair list
        let items: Vec<_> = stats
            .differences
            .keys()
            .map(|(a, b)| ListItem::new(format!("{a}-{b}")))
            .collect();
        let list = List::new(items).highlight_symbol(">").block(
            Block::default()
                .borders(Borders::RIGHT)
                .border_style(Style::default().add_modifier(Modifier::DIM)),
        );
        f.render_stateful_widget(list, chunks[0], &mut self.differences_list_state);

        // Baseline information about the difference finding
        let difference_stats = stats
            .differences
            .values()
            .nth(self.differences_list_state.selected().unwrap_or(0))
            .unwrap();
        let total = difference_stats.total;
        let width = (total as f64).log10().ceil() as usize;

        let rows = [
            ("Total", difference_stats.total),
            ("Equal", difference_stats.no_diff),
            ("Insignificant", difference_stats.insignificant),
            ("Significant", difference_stats.significant),
            ("Equal (R)", difference_stats.repro_no_diff),
            ("Insignificant (R)", difference_stats.repro_insignificant),
            (
                "Significant (other, R)",
                difference_stats.repro_significant_other,
            ),
            ("Significant (R)", difference_stats.repro_significant),
        ]
        .into_iter()
        .map(|(name, count)| {
            Row::new([Cell::from(name), App::num_cell(count, total, width, None)])
        });

        let tbl = Table::new(rows)
            // Columns widths are constrained in the same way as Layout...
            .widths(&[Constraint::Length(25), Constraint::Min(20)])
            .header(
                Row::new(vec!["Kind", "Count"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1);
        f.render_stateful_widget(tbl, chunks[1], &mut self.differences_table_state);

        // Special listing of only the difference kinds
        let rows = difference_stats.per_diff_kind.iter().map(|(name, &count)| {
            Row::new([
                Cell::from(name.as_ref()),
                App::num_cell(count, total, width, None),
            ])
        });

        let tbl = Table::new(rows)
            // Columns widths are constrained in the same way as Layout...
            .widths(&[Constraint::Length(30), Constraint::Min(20)])
            .header(
                Row::new(vec!["DiffKind", "Count"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1);
        if difference_stats.per_diff_kind.len() >= chunks[2].height as usize {
            log::warn!("Not enough space to render all difference kinds");
        }
        f.render_stateful_widget(tbl, chunks[2], &mut self.differences_table_state);

        // Special listing of only the difference categories
        let rows = difference_stats
            .per_diff_category
            .iter()
            .map(|(name, &count)| {
                Row::new([
                    Cell::from(name.as_ref()),
                    App::num_cell(count, total, width, None),
                ])
            });

        let tbl = Table::new(rows)
            // Columns widths are constrained in the same way as Layout...
            .widths(&[Constraint::Length(30), Constraint::Min(20)])
            .header(
                Row::new(vec!["DiffCategory", "Count"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1);
        if difference_stats.per_diff_kind.len() >= chunks[3].height as usize {
            log::warn!("Not enough space to render all difference categories");
        }
        f.render_stateful_widget(tbl, chunks[3], &mut self.differences_table_state);
    }

    fn num_cell(
        num: u64,
        total: impl Into<Option<u64>>,
        width: usize,
        time: Option<u64>,
    ) -> Cell<'static> {
        if let Some(total) = total.into() {
            let perc = if total == 0 {
                0.0
            } else {
                num as f64 * 100.0 / total as f64
            };
            if let Some(seconds) = time {
                let per_sec = num as f64 / seconds as f64;
                Cell::from(format!(
                    "{num: >width$} ({perc: >5.1}%)\n{per_sec: >width$.2}/s",
                ))
            } else {
                Cell::from(format!("{num: >width$} ({perc: >5.1}%)"))
            }
        } else {
            Cell::from(format!("{num: >width$}"))
        }
    }
}

struct FormattedDuration(Duration);

impl std::fmt::Display for FormattedDuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        fn item_plural(
            f: &mut Formatter<'_>,
            started: &mut bool,
            name: &str,
            value: u64,
        ) -> std::fmt::Result {
            if value > 0 {
                if *started {
                    f.write_str(" ")?;
                }
                write!(f, "{value}{name}")?;
                if value > 1 {
                    f.write_str("s")?;
                }
                *started = true;
            }
            Ok(())
        }

        fn item(
            f: &mut Formatter<'_>,
            started: &mut bool,
            name: &str,
            value: u32,
        ) -> std::fmt::Result {
            if value > 0 {
                if *started {
                    f.write_str(" ")?;
                }
                write!(f, "{value}{name}")?;
                *started = true;
            }
            Ok(())
        }

        let secs = self.0.as_secs();

        if secs == 0 {
            f.write_str("0s")?;
            return Ok(());
        }

        const MINUTE: u64 = 60;
        const HOUR: u64 = MINUTE * 60;
        const DAY: u64 = HOUR * 24;
        const MONTH: u64 = DAY * 30;
        const YEAR: u64 = DAY * 365;

        let years = secs / YEAR; // 365.25d
        let ydays = secs % YEAR;
        let months = ydays / MONTH; // 30.44d
        let mdays = ydays % MONTH;
        let days = mdays / DAY;
        let day_secs = mdays % DAY;
        let hours = day_secs / HOUR;
        let minutes = day_secs % HOUR / MINUTE;
        let seconds = day_secs % MINUTE;

        let started = &mut false;
        item_plural(f, started, "year", years)?;
        item_plural(f, started, "month", months)?;
        item_plural(f, started, "day", days)?;
        item(f, started, "h", hours as u32)?;
        item(f, started, "m", minutes as u32)?;
        item(f, started, "s", seconds as u32)?;
        Ok(())
    }
}

struct TerminalGuard;

impl TerminalGuard {
    /// Creates a new RawModeGuard and enters raw mode.
    fn new() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(
            stdout,
            EnterAlternateScreen,
            cursor::Hide,
            Clear(ClearType::All)
        )?;
        Ok(Self {})
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        eprintln!("Dropping TerminalGuard");
        let mut stdout = io::stdout();
        let _ = execute!(stdout, cursor::Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}
