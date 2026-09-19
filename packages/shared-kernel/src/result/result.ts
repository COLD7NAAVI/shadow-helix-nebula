/**
 * Shadow : Helix Nebula (SHN) — Algebraic Result Monad
 *
 * Enforces SEC-INV-15: Deterministic, fail-closed error propagation without throwing untyped exceptions.
 */

export type Result<T, E> = Ok<T, E> | Err<T, E>;

export class Ok<T, E = never> {
  readonly isOk = true;
  readonly isErr = false;

  constructor(readonly value: T) {}

  map<U>(fn: (val: T) => U): Result<U, E> {
    return new Ok<U, E>(fn(this.value));
  }

  mapErr<F>(_fn: (err: E) => F): Result<T, F> {
    return new Ok<T, F>(this.value);
  }

  flatMap<U, F>(fn: (val: T) => Result<U, F>): Result<U, E | F> {
    return fn(this.value);
  }

  unwrapOr(_defaultValue: T): T {
    return this.value;
  }

  match<U>(patterns: { ok: (val: T) => U; err: (err: E) => U }): U {
    return patterns.ok(this.value);
  }
}

export class Err<T, E> {
  readonly isOk = false;
  readonly isErr = true;

  constructor(readonly error: E) {}

  map<U>(_fn: (val: T) => U): Result<U, E> {
    return new Err<U, E>(this.error);
  }

  mapErr<F>(fn: (err: E) => F): Result<T, F> {
    return new Err<T, F>(fn(this.error));
  }

  flatMap<U, F>(_fn: (val: T) => Result<U, F>): Result<U, E | F> {
    return new Err<U, E | F>(this.error);
  }

  unwrapOr(defaultValue: T): T {
    return defaultValue;
  }

  match<U>(patterns: { ok: (val: T) => U; err: (err: E) => U }): U {
    return patterns.err(this.error);
  }
}

export function ok<T, E = never>(value: T): Result<T, E> {
  return new Ok<T, E>(value);
}

export function err<T = never, E = unknown>(error: E): Result<T, E> {
  return new Err<T, E>(error);
}

export type Option<T> = Some<T> | None;

export class Some<T> {
  readonly isSome = true;
  readonly isNone = false;
  constructor(readonly value: T) {}

  unwrapOr(_defaultValue: T): T {
    return this.value;
  }
}

export class None {
  readonly isSome = false;
  readonly isNone = true;

  unwrapOr<T>(defaultValue: T): T {
    return defaultValue;
  }
}

export const none = new None();
export function some<T>(value: T): Option<T> {
  return new Some<T>(value);
}
