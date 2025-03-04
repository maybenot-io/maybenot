# Changelog

Manually generated changelog, for now. We follow semantic versioning.

## XXX - XXX

- The version of the simulator now longer tracks the framework and instead
  follows SemVer compatible updates.
- Completely reworked aggregated delays due to blocking, now tracked separately
  at client and server. *When* blocking should go into effect is a function of
  network delay (when we might have packet interdependencies). *How much* delay
  should be added is split into separate logic for blocking expiry and padding
  with bypass and replace set. There is a a 1ms window (TODO:tune or parameter?)
  within other packets part of the same burst (conceptually) will reduce the
  amount of delay.

## 2.0.1 - 2024-10-24

- Bumped together with framework to v2.0.1.

## 2.0.0 - 2024-09-09

- Update to Maybenot v2.0.0.
- Added a simple network model, allowing advanced users to simulate a maximum
  packets-per-second (PPS) bottleneck.
- Crude, probably too aggressive, support for simulating aggregated delays due
  to blocking actions preventing normal traffic from being sent.

## 1.1.1 - 2024-04-08

- Update to Maybenot v1.1.0.

## 1.1.0 - 2024-04-05

- Support for integration delays.
- Light networking refactor.

## 1.0.1 - 2023-11-24

- Minor README update.

## 1.0.0 - 2023-11-24

- Initial public release of the Maybenot simulator.
