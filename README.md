# fswalker

A simple and fast file system integrity checking tool in Go.

## Overview

fswalker consists of two parts:

*   **Walker**: The walker collects information about the target machine's file
    system and writes the collected list out in binary proto format. The walker
    policy defines which directories to include and exclude.

*   **Reporter**: The reporter is a tool which runs outside of the target
    machine and compares two runs (aka Walks) with each other and reports the
    diffs, if any. The report config defines which
    directories to include and exclude.

Note: The walker and the reporter have two separate definitions of directories
to include and exclude. This is done on purpose so more information can be
collected than what is later reviewed. If something suspicious comes up, it is
always possible to see more changes than the ones deemed "interesting" in the
first place.

Why using fswalker instead of using existing solutions such as Tripwire,
AIDE, Samhain, etc?

*  It's opensource and actively developed.
*  All data formats used are open as well and thus allow easy imports and
   exports.
*  It's easily expandable with local modifications.
*  No dependencies on non-standard Go libraries outside github.com/google.

## Installation

```bash
go get github.com/google/fswalker/cmd/walker
go get github.com/google/fswalker/cmd/reporter
```

## Configuration

### Walker Policy

The Walker policy specifies how a file system is walked and what to write to the
output file. Most notably, it contains a list of includes and excludes.

*  **include**: Includes are starting points for the file walk. All includes are
   walked simultaneously.

*  **exclude_pfx**: Excludes are specified as prefixes. They are literal string
   prefix matches. To make this more clear, let's assume we have an `include` of
   "/" and an `exclude_pfx` of "/home". When the walker evaluates "/home", it
   will skip it because the prefix matches. However, it also skips
   "/homeofme/important.file".

Refer to the proto buffer description to see a complete reference of all
options and their use.

The following constitutes a functional example for Ubuntu:

policy.textpb

```protobuf
version: 1
max_hash_file_size: 1048576
walk_cross_device: true
ignore_irregular_files: false
include: "/"
exclude_pfx: "/usr/local/"
exclude_pfx: "/usr/src/"
exclude_pfx: "/usr/share/"
exclude_pfx: "/var/backups/"
exclude_pfx: "/var/cache/"
exclude_pfx: "/var/log/"
exclude_pfx: "/var/mail/"
exclude_pfx: "/var/spool/"
exclude_pfx: "/var/tmp/"
```

### Reporter Config

The reporter allows to specify fewer things in its config, notably excludes.
The reason to have additional excludes in the reporter is simple: It allows
recording more details in the walks and fewer to be reported. If something
suspicious is ever found, it allows going back to previous walks however and
check what the status was back then.

*  **exclude_pfx**: Excludes are specified as prefixes. They are literal string
   prefix matches. To make this more clear, let's assume we have an `include` of
   "/" and an `exclude_pfx` of "/home". When the walker evaluates "/home", it
   will skip it because the prefix matches. However, it also skips
   "/homeofme/important.file".

The following constitutes a functional example for Ubuntu:

config.textpb

```protobuf
version: 1
exclude_pfx: "/root/"
exclude_pfx: "/home/"
exclude_pfx: "/tmp/"
```

Refer to the proto buffer description to see a complete reference of all
options.

### Review File

The following constitutes a functional example:

reviews.textpb

```protobuf
review: {
  key: "some-host.google.com"
  value: {
    walk_id: "457ab084-2426-4ca8-b54c-cefdce543042"
    walk_reference: "/tmp/some-host.google.com-20181205-060000-fswalker-state.pb"
    fingerprint: {
      method: SHA256
      value: "0bfb7506e44dbca14914c3250b2d4d5be005d0de4460c9f298f227bac096f642"
    }
  }
}
```

Refer to the proto buffer description to see a complete reference of all
options.

## Examples

The following examples show how to run both the walker and the reporter.

Note that there are libraries for each which can be used independently if so
desired. See the implementations of walker and reporter main for a reference on
how to use the libraries.

### Walker

Once you have a policy as [described above](#walker-policy), you can run the
walker:

```bash
walker \
  -policyFile=policy.textpb \
  -outputFilePfx="/tmp"
```

Add `-verbose` to see more details about what's going on.

### Reporter

Once you have a config as [described above](#reporter-config) and more than one
Walk file, you can run the reporter.

Add `-verbose` to see more details about what's going on.

To allow for easier reviews, `-paginate` allows to invoke `$PAGER` (or `less`
if `$PAGER` is not set) to page through the results.

#### Direct Comparison

The simplest way to run it is to directly specify two Walk files to compare
against each other:

```bash
reporter \
  -configFile=config.textpb \
  -beforeFile=/tmp/some-host.google.com-20181205-060000-fswalker-state.pb \
  -afterFile=/tmp/some-host.google.com-20181206-060000-fswalker-state.pb \
  -paginate
```

Note that you can also run with just `-afterFile` specified which will basically
list all files as newly added. This is only really useful with a new machine.

#### Review File Based

Contrary to the above example, reporter would normally be run with a review
file:

```bash
reporter \
  -configFile=config.textpb \
  -reviewFile=reviews.textpb \ # this needs to be writeable!
  -walkPath=/tmp \
  -hostname=some-host.google.com \
  -paginate
```

The reporter runs, displays all diffs and when deemed ok, updates the reviewFile
with the latest "known good" information.

The idea is that the review file contains a set of "known good" states and is
under version control and four-eye principle / reviews.

## Development

### Protocol Buffer

If you change the protocol buffer, ensure you generate a new Go library based on it:

```bash
go generate
```

(The rules for `go generate` are in `fswalker.go`.)

## License

Apache 2.0

This is not an officially supported Google product
