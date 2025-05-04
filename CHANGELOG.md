## v1.0.0 - 2025-05-04 - Long overdue 1.0

Noteworthy Changes:

* Complete removal of SPF record support, records should be transitioned to TXT
  values before updating to this version.
* Removal of support for legacy `geo` targeting, records should be transitioned
  to `dynamic` before updating to this version.

Changes:

* Address pending octoDNS 2.x deprecations, require minimum of 1.5.x

## v0.0.5 - 2023-12-xx - Root NS support

* Add support for root NS updates

## v0.0.4 - 2023-04-27 - ALIAS support

* add support for ALIAS as a CNAME at root
* Fixed validation of unsupported provinces
* API requests set a user agent with version

## v0.0.3 - 2022-11-21 - EdgeCenterProvider

* EdgeCenterProvider added

## v0.0.2 - 2022-05-26 - Forward rather than reverse

* Remove changes.reverse from apply so that things are applied in the octoDNS
  best practice order: Deletes, Creates, Updates.

## v0.0.1 - 2022-01-11 - Moving

#### Nothworthy Changes

* Initial extraction of GCoreProvider from octoDNS core

#### Stuff

Nothing
