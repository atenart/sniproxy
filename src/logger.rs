use std::{io::Write, sync::Mutex};

use anyhow::Result;
use log::{LevelFilter, Metadata, Record};
use termcolor::{BufferedStandardStream, Color, ColorChoice, ColorSpec, WriteColor};
use time::{OffsetDateTime, macros::format_description};

use crate::context::REQ_CONTEXT;

/// Our own simple logger.
pub(crate) struct Logger {
    /// Max level the logger will output.
    max_level: LevelFilter,
    /// We can output messages to stdout and stderr depending on their severity.
    stdout: Mutex<BufferedStandardStream>,
    stderr: Mutex<BufferedStandardStream>,
}

impl Logger {
    pub(crate) fn init(max_level: LevelFilter) -> Result<()> {
        log::set_max_level(max_level);
        log::set_boxed_logger(Box::new(Self {
            max_level,
            stdout: Mutex::new(BufferedStandardStream::stdout(ColorChoice::Auto)),
            stderr: Mutex::new(BufferedStandardStream::stderr(ColorChoice::Auto)),
        }))?;
        Ok(())
    }

    fn try_log(&self, out: &mut BufferedStandardStream, record: &Record) -> Result<()> {
        static LEVEL_COLORS: &[Option<Color>] = &[
            None,                // Default.
            Some(Color::Red),    // Error.
            Some(Color::Yellow), // Warn.
            Some(Color::Blue),   // Info.
            Some(Color::Cyan),   // Debug.
            Some(Color::White),  // Trace.
        ];

        // If the log level allows debug! and or trace! messages, show time
        // time.
        if self.max_level >= LevelFilter::Debug {
            OffsetDateTime::now_utc().format_into(
                out,
                format_description!("[hour]:[minute]:[second]:[subsecond digits:6] "),
            )?;
        }

        // If we have a request context, use it. Silence access errors, the
        // context is not mandatory.
        if let Ok(ret) = REQ_CONTEXT.try_with(|context| -> Result<()> {
            let context = context.borrow();
            write!(out, "{}>{} ", context.peer, context.local)?;
            if let Some(hostname) = &context.hostname {
                write!(out, "({hostname}) ")?;
            }
            Ok(())
        }) {
            ret?;
        }

        // Show the level for error! and warn! messages, or if the max level
        // includes debug!.
        if record.level() <= LevelFilter::Warn || self.max_level >= LevelFilter::Debug {
            out.set_color(ColorSpec::new().set_fg(LEVEL_COLORS[record.level() as usize]))?;
            write!(out, "{:5} ", record.level())?;
            out.reset()?;
        }

        // Finally write the log message and flush it.
        writeln!(out, "{}", record.args())?;
        out.flush()?;

        Ok(())
    }
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // Select the output based on the log level.
        let mut out = match record.level() {
            level if level == LevelFilter::Error => self.stderr.lock().unwrap(),
            _ => self.stdout.lock().unwrap(),
        };

        // Not much we can do to report the error.
        let _ = self.try_log(&mut out, record);
    }

    fn flush(&self) {
        // Not much we can do to report the errors.
        let _ = self.stdout.lock().unwrap().flush();
        let _ = self.stderr.lock().unwrap().flush();
    }
}
