# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Save and replay of decoded sessions: `--save FILE` tees every decoded record
  to versioned JSONL while capture continues, and `--replay FILE` reopens a
  saved session without live capture. In the TUI, `:save` (`:w`) and `:open`
  (`:o`) do the same from the command bar. The on-disk schema (version 1) is
  documented in [`docs/session-format.md`](docs/session-format.md).

## [0.3.0]

## [0.2.0]

## [0.1.0]

Release notes for 0.3.0 and earlier are on the project's
[GitHub releases](https://github.com/sunng87/tapgres/releases) page; this file
tracks changes going forward.
