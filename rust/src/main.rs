use std::process::Command;
use std::io::{self, Write};

fn main() {
    println!("Configuration du Raspberry Pi via Rust");

    // Exemple: Afficher la version du système
    let uname = Command::new("uname")
        .arg("-a")
        .output()
        .expect("Échec de l'exécution de uname");
    println!("Version système: {}", String::from_utf8_lossy(&uname.stdout));

    // Exemple: Modifier la configuration (remplacer par vos commandes)
    // Ici, on demande à l'utilisateur s'il veut activer SSH
    print!("Voulez-vous activer SSH ? (o/n): ");
    io::stdout().flush().unwrap();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).unwrap();

    if answer.trim().eq_ignore_ascii_case("o") {
        let status = Command::new("sudo")
            .arg("systemctl")
            .arg("enable")
            .arg("--now")
            .arg("ssh")
            .status()
            .expect("Échec de l'activation de SSH");
        if status.success() {
            println!("SSH activé !");
        } else {
            println!("Erreur lors de l'activation de SSH.");
        }
    } else {
        println!("SSH non activé.");
    }

}