use nfq::Verdict;
use tinyfiledialogs::{message_box_yes_no, MessageBoxIcon::Question, YesNo};

const DEFAULT_CHOICE: YesNo = YesNo::Yes;

pub fn prompt_verdict(msg: &str) -> Verdict {
    match message_box_yes_no("Firewall", msg, Question, DEFAULT_CHOICE) {
        YesNo::Yes => Verdict::Accept,
        YesNo::No => Verdict::Drop,
    }
}
