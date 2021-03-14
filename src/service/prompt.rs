use dialog::DialogBox;
use nfq::Verdict;

const DEFAULT_VERDICT: Verdict = Verdict::Drop;

pub fn prompt_verdict(msg: &str) -> Verdict {
    match dialog::Question::new(msg)
    .title("Firewall")
    .show()
    {
        Ok(dialog::Choice::Yes) => {
            Verdict::Accept
        }
        Ok(dialog::Choice::No) => {
            Verdict::Drop
        }
        Ok(dialog::Choice::Cancel) | Err(_) => {
            warn!(
                "could not prompt using default verdict {:?}",
                DEFAULT_VERDICT
            );
            DEFAULT_VERDICT
        }
    }
}
