<?php

declare(strict_types=1);

namespace Monosecret;

/** The kind of a failed cross-secret presence constraint. */
enum ConstraintViolationKind: string
{
    case AtLeastOne = 'at_least_one';
    case ExactlyOne = 'exactly_one';
}
