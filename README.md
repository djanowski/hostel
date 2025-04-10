# Hostel

Hostel is a simple command line tool to run all your projects
in a given directory and expose them via HTTPS on `https://[project].localhost`.

## Why

- I don't want to mess with random port numbers which sometimes have to be
coordinated with other engineers if you have things like redirect URLs for OAuth, etc.
- I want to use HTTPS like I would in production.
- I'd rather not set up daemons

## Usage

```
$ hostel ~/path/to/projects
```

Hostel will discover web projects in the given directory and start a local
web server for each of them. Logs are combined and printed to standard output.

For now, projects are discovered by looking for a `package.json` file
and the server is started by running `npm run dev`. This is a very early
version and I plan to add support for other project types, mainly using `Procfile.dev`.

## Installation

```
go install github.com/djanowski/hostel
```

Or get it from the GitHub Releases page: https://github.com/djanowski/hostel/releases.

More installation options coming soon.

## Roadmap

- Use a custom certificate authority to generate a trusted wildcard TLS certificate
- Support for other project types using `Procfile.dev`
- Explore options to remove the need for `/etc/resolvers`
- Automatically start and stop the web server based on usage
