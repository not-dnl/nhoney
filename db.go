package main

import (
	"database/sql"
	"encoding/json"
	"github.com/charmbracelet/log"
	_ "github.com/mattn/go-sqlite3"
)

func initDB() *sql.DB {
	db, err := sql.Open("sqlite3", "./db/db.db")
	if err != nil {
		log.Errorf("Error Opening DB: %s", err)
		return nil
	}

	createResultsTableSQL := `
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT,
        port INTEGER,
        honeypot_variant TEXT,
        is_honeypot INTEGER                    
    );`

	_, err = db.Exec(createResultsTableSQL)
	if err != nil {
		log.Errorf("Error Executing query: %s", err)
		return nil
	}

	createShodanTableSQL := `
    CREATE TABLE IF NOT EXISTS shodan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT UNIQUE,
        is_honeypot_shodan INTEGER,
        open_ports TEXT,
        vulns TEXT,
        cpes TEXT
    );`

	_, err = db.Exec(createShodanTableSQL)
	if err != nil {
		log.Errorf("Error Executing query: %s", err)
		return nil
	}

	return db
}

func insertResult(db *sql.DB, results []Result) error {
	stmtResults, err := db.Prepare("INSERT INTO results (host, port, honeypot_variant, is_honeypot) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmtResults.Close()

	stmtShodan, err := db.Prepare("INSERT OR IGNORE INTO shodan (host, is_honeypot_shodan, open_ports, vulns, cpes) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmtShodan.Close()

	for _, result := range results {
		_, err := stmtResults.Exec(result.IP, result.Port, result.HoneypotVariant, result.IsHoneypot)
		if err != nil {
			return err
		}

		openPortsJSON, err := json.Marshal(result.OpenPorts)
		if err != nil {
			return err
		}

		vulnsJSON, err := json.Marshal(result.Vulns)
		if err != nil {
			return err
		}

		cpesJSON, err := json.Marshal(result.Cpes)
		if err != nil {
			return err
		}

		_, err = stmtShodan.Exec(result.IP, result.IsHoneypotShodan, string(openPortsJSON), string(vulnsJSON), string(cpesJSON))
		if err != nil {
			return err
		}
	}

	return nil
}

func removeExistingEntriesFromArray(db *sql.DB, IPs []string) []string {
	rows, err := db.Query("SELECT DISTINCT host FROM results")
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	dbItems := make(map[string]bool)
	for rows.Next() {
		var item string
		if err := rows.Scan(&item); err != nil {
			panic(err)
		}
		dbItems[item] = true
	}
	if err := rows.Err(); err != nil {
		panic(err)
	}

	var newArray []string
	for _, ip := range IPs {
		if !dbItems[ip] {
			newArray = append(newArray, ip)
		}
	}

	return newArray
}
