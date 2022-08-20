<?php

declare(strict_types=1);

namespace KeycloakGuard;

use Auth0\SDK\Exception\InvalidTokenException;

class Validator
{
    /**
     * Array representing the claims of a JWT.
     *
     * @var array<string,array<int|string>|int|string>
     */
    private array $claims;

    /**
     * Constructor for the Token Validator class.
     *
     * @param array<string,array<int|string>|int|string> $claims Array representing the claims of a JWT.
     */
    public function __construct(
        array $claims
    ) {
        $this->claims = $claims;
    }

    /**
     * Validate the 'aud' claim.
     *
     * @param array<string> $expects An array of allowed values for the 'aud' claim. Successful if ANY match.
     *
     * @throws InvalidTokenException When claim validation fails.
     */
    public function audience(
        array $expects
    ): self {
        $audience = $this->getClaim('aud');

        if ($audience === null) {
            throw InvalidTokenException::missingAudienceClaim();
        }

        if (! is_array($audience)) {
            $audience = [ $audience ];
        }

        if (array_intersect($audience, $expects) !== []) {
            return $this;
        }

        throw InvalidTokenException::mismatchedAudClaim(implode(', ', $expects), implode(', ', $audience));
    }

    /**
     * Validate the 'auth_time' claim.
     *
     * @param int      $maxAge Maximum window of time in seconds since the 'auth_time' to accept the token.
     * @param int      $leeway Leeway in seconds to allow during time calculations.
     * @param int|null $now    Optional. Unix timestamp representing the current point in time to use for time calculations.
     *
     * @throws InvalidTokenException When claim validation fails.
     */
    public function authTime(
        int $maxAge,
        int $leeway = 60,
        ?int $now = null
    ): self {
        $authTime = $this->getClaim('auth_time');
        $now ??= time();

        if ($authTime === null || ! is_numeric($authTime)) {
            throw InvalidTokenException::missingAuthTimeClaim();
        }

        $validUntil = (int) $authTime + $maxAge + $leeway;

        if ($now > $validUntil) {
            throw InvalidTokenException::mismatchedAuthTimeClaim($now, $validUntil);
        }

        return $this;
    }

    /**
     * Validate the 'azp' claim.
     *
     * @param array<string> $expects An array of allowed values for the 'azp' claim. Successful if ANY match.
     *
     * @throws InvalidTokenException When claim validation fails.
     */
    public function authorizedParty(
        array $expects
    ): self {
        $audience = $this->getClaim('aud');

        if ($audience === null) {
            throw InvalidTokenException::missingAudienceClaim();
        }

        if (is_array($audience)) {
            $azp = $this->getClaim('azp');

            if ($azp === null || ! is_string($azp)) {
                throw InvalidTokenException::missingAzpClaim();
            }

            if (! in_array($azp, $expects, true)) {
                throw InvalidTokenException::mismatchedAzpClaim(implode(', ', $expects), $azp);
            }
        }

        return $this;
    }

    /**
     * Validate the 'exp' claim.
     *
     * @param int      $leeway Leeway in seconds to allow during time calculations.
     * @param int|null $now    Optional. Unix timestamp representing the current point in time to use for time calculations.
     *
     * @throws InvalidTokenException When claim validation fails.
     */
    public function expiration(
        int $leeway = 60,
        ?int $now = null
    ): self {
        $expires = $this->getClaim('exp');
        $now ??= time();

        if ($expires === null || ! is_numeric($expires)) {
            throw InvalidTokenException::missingExpClaim();
        }

        $expires = (int) $expires + $leeway;

        if ($now > $expires) {
            throw InvalidTokenException::mismatchedExpClaim($now, $expires);
        }

        return $this;
    }

    /**
     * Validate the 'iat' claim is present.
     *
     * @throws InvalidTokenException When claim validation fails.
     */
    public function issued(): self
    {
        $issued = $this->getClaim('iat');

        if ($issued === null) {
            throw InvalidTokenException::missingIatClaim();
        }

        return $this;
    }

    /**
     * Validate the 'iss' claim.
     *
     * @param string $expects The value to compare with the claim.
     *
     * @throws InvalidTokenException When claim validation fails.
     */
    public function issuer(
        string $expects
    ): self {
        $claim = $this->getClaim('iss');

        if ($claim === null || ! is_string($claim)) {
            throw InvalidTokenException::missingIssClaim();
        }

        if ($claim !== $expects) {
            throw InvalidTokenException::mismatchedIssClaim($expects, $claim);
        }

        return $this;
    }


    /**
     * Return a claim by it's key. Null if not present.
     *
     * @param string $key The claim key to search for.
     *
     * @return array<mixed>|int|string|null
     */
    private function getClaim(string $key) {
        if (! isset($this->claims[$key])) {
            return null;
        }

        return $this->claims[$key];
    }
}
