use configparser::ini::Ini;

pub struct Config {
    config: Ini,
}

impl Config {
    pub fn load(file: &str) -> Config {
        let mut config = Ini::new();
        if config.load(file).is_err() {
            eprintln!("failed to load config file");
        }
        Config { config }
    }

    pub fn get_log_level(&self) -> String {
        self.config.get("LOG", "level").unwrap_or("info".into())
    }

    pub fn get_log_file(&self) -> String {
        self.config
            .get("LOG", "file")
            .unwrap_or("/tmp/firewall.log".into())
    }

    pub fn get_rules(&self) -> Option<Vec<String>> {
        println!("{:?}", self.config.get_map_ref());
        Some(
            self.config
                .get_map_ref()
                .get("rules")?
                .keys()
                .map(|a| a.clone())
                .collect(),
        )
    }
}
