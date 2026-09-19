import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ok, err, some, none } from '../dist/index.js';

describe('Result & Option Monads', () => {
  it('should support functional map on Ok', () => {
    const res = ok(10).map((n) => n * 2);
    assert.equal(res.isOk, true);
    assert.equal(res.unwrapOr(0), 20);
  });

  it('should bypass map on Err and preserve error', () => {
    const res = err<number, string>('Initial failure').map((n) => n * 2);
    assert.equal(res.isErr, true);
    assert.equal(res.unwrapOr(0), 0);
  });

  it('should support flatMap chaining', () => {
    const divide = (n: number, d: number) =>
      d === 0 ? err('Division by zero') : ok(n / d);

    const res = ok(20)
      .flatMap((n) => divide(n, 2))
      .flatMap((n) => divide(n, 5));

    assert.equal(res.isOk, true);
    assert.equal(res.unwrapOr(0), 2);

    const failed = ok(20)
      .flatMap((n) => divide(n, 0))
      .flatMap((n) => divide(n, 5));

    assert.equal(failed.isErr, true);
    if (failed.isErr) {
      assert.equal(failed.error, 'Division by zero');
    }
  });

  it('should support pattern matching via match()', () => {
    const val = ok('payload').match({
      ok: (v) => `Processed: ${v}`,
      err: (e) => `Error: ${e}`,
    });
    assert.equal(val, 'Processed: payload');
  });

  it('should support Option Some/None operations', () => {
    const optSome = some('data');
    assert.equal(optSome.isSome, true);
    assert.equal(optSome.unwrapOr('default'), 'data');

    const optNone = none;
    assert.equal(optNone.isNone, true);
    assert.equal(optNone.unwrapOr('default'), 'default');
  });
});
