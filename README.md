# 🔒 URL Security Checker

**By CF Security**

A Java command-line tool that helps you decide whether a link is safe before you click it. 🕵️
It first runs quick pre-tests: it checks for URL shorteners, looks the URL up in a PostgreSQL database of known malicious URLs, and compares it against a list of the world's most trusted sites. 🌐
If the URL isn't cleared by those, further tests analyse it and give it a danger rating. ⚠️
The whole thing runs in Docker, so you can be up and running with two commands. 🐳

## 📋 Requirements

- 🐳 Docker Desktop (for the Docker option), or
- ☕ Java 17+ and PostgreSQL (for the IDE option)

## 🚀 Run with Docker (recommended)

From the project folder:

```
docker compose up -d postgres_db
docker compose run --rm url_analyzer_app
```

🗄️ The database table and sample data are created automatically from `init.sql` the first time the database starts.

🔧 After changing `Main.java`, rebuild before running:

```
docker compose build
```

🛑 To stop everything and keep your data:

```
docker compose down
```

🧹 To stop everything and wipe the database (it is re-created from `init.sql` next time):

```
docker compose down -v
```

## 💻 Run from an IDE

1. Start only the database: `docker compose up -d postgres_db`
2. Add `postgresql-42.7.13.jar` to your project as a library.
3. Set these environment variables in your run configuration:
   - `DB_USER=cf_checker`
   - `DB_PASS=CF21@dmin`
4. Run `Main`. `DB_HOST` defaults to `localhost`, so leave it unset.

To use your own PostgreSQL instead, run `init.sql` against it and set `DB_USER` and `DB_PASS` to match.

## ⚙️ Configuration

| Variable  | Purpose           | Default     |
|-----------|-------------------|-------------|
| `DB_HOST` | Database host     | `localhost` |
| `DB_USER` | Database user     | `postgres`  |
| `DB_PASS` | Database password | (required)  |

## 📁 Files

| File                     | Purpose                                    |
|--------------------------|--------------------------------------------|
| `Main.java`              | The application                            |
| `Dockerfile`             | Builds the Java app image                  |
| `docker-compose.yml`     | Runs the app and the PostgreSQL database   |
| `init.sql`               | Creates and seeds the `url_database` table |
| `postgresql-42.7.13.jar` | PostgreSQL JDBC driver                     |

## ⚠️ Note

The credentials in `docker-compose.yml` are for a local test database only. Do not reuse them anywhere real.
