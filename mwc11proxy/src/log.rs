use chrono::Local;
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};

pub struct ConsoleLogger;

impl ConsoleLogger {
    pub fn init(self) -> Result<(), SetLoggerError> {
        log::set_max_level(LevelFilter::Info);
        log::set_boxed_logger(Box::new(self))?;
        Ok(())
    }
}

impl Log for ConsoleLogger {
    fn enabled(&self, meta: &Metadata) -> bool {
        meta.level() <= Level::Trace
    }

    fn log(&self, rec: &Record) {
        let time = Local::now().format("%Y-%m-%d %H:%M:%S.%3f");
        println!("{} {:<5} {}", time, rec.level(), rec.args());
    }

    fn flush(&self) {
        /* do nothing */
    }
}
