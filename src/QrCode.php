<?php

declare(strict_types=1);

namespace NolvikoExt\Totp;

use InvalidArgumentException;

/**
 * A small QR code encoder (ISO/IEC 18004) without dependencies (owner decision 2026-11-15): byte mode, error
 * correction level M, versions 1-20 (up to 666 bytes; an otpauth address needs about 120). The mask is chosen
 * by the standard penalty rules 1, 2 and 4. Output is an SVG of plain path data, safe to print as HTML.
 */
final class QrCode
{
    /** Error-correction codewords per block, level M, versions 1-20. */
    private const ECC = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26];

    /** Error-correction blocks, level M, versions 1-20. */
    private const BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16];

    private int $size;

    /** @var list<list<bool>> [y][x] */
    private array $modules = [];

    /** @var list<list<bool>> [y][x] */
    private array $function = [];

    private function __construct(private readonly int $version)
    {
        $this->size = $version * 4 + 17;
        $this->modules = array_fill(0, $this->size, array_fill(0, $this->size, false));
        $this->function = $this->modules;
    }

    /**
     * @param int|null $forceMask 0-7 to skip the penalty choice (tests compare with other encoders).
     *
     * @return list<list<bool>> Dark modules, [y][x], without the quiet zone.
     */
    public static function matrix(string $data, ?int $forceMask = null): array
    {
        $length = strlen($data);
        $version = 0;
        for ($candidate = 1; $candidate <= 20; ++$candidate) {
            if (4 + ($candidate < 10 ? 8 : 16) + 8 * $length <= self::dataCodewords($candidate) * 8) {
                $version = $candidate;
                break;
            }
        }
        if ($version === 0) {
            throw new InvalidArgumentException('qr_data_too_long');
        }

        $qr = new self($version);
        $qr->drawFunctionPatterns();
        $qr->drawCodewords($qr->interleave(self::encode($data, $version)));

        $best = 0;
        $lowest = PHP_INT_MAX;
        for ($mask = 0; $mask < 8; ++$mask) {
            $qr->applyMask($mask);
            $qr->drawFormatBits($mask);
            $penalty = $qr->penalty();
            if ($penalty < $lowest) {
                [$best, $lowest] = [$mask, $penalty];
            }
            $qr->applyMask($mask);
        }
        $best = $forceMask ?? $best;
        $qr->applyMask($best);
        $qr->drawFormatBits($best);

        return $qr->modules;
    }

    /** An SVG image with a four-module quiet zone; $pixels is the drawn width and height. */
    public static function svg(string $data, int $pixels = 220): string
    {
        $matrix = self::matrix($data);
        $size = count($matrix) + 8;
        $path = '';
        foreach ($matrix as $y => $row) {
            foreach ($row as $x => $dark) {
                if ($dark) {
                    $path .= 'M' . ($x + 4) . ',' . ($y + 4) . 'h1v1h-1z';
                }
            }
        }

        return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' . $size . ' ' . $size . '" width="' . $pixels
            . '" height="' . $pixels . '" shape-rendering="crispEdges" role="img" aria-hidden="true">'
            . '<rect width="' . $size . '" height="' . $size . '" fill="#ffffff"/>'
            . '<path d="' . $path . '" fill="#000000"/></svg>';
    }

    /** @return list<int> Data codewords: byte mode, count, data, terminator, padding. */
    private static function encode(string $data, int $version): array
    {
        $capacity = self::dataCodewords($version) * 8;
        $bits = '0100' . str_pad(decbin(strlen($data)), $version < 10 ? 8 : 16, '0', STR_PAD_LEFT);
        foreach (str_split($data) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }
        $bits .= str_repeat('0', min(4, $capacity - strlen($bits)));
        $bits .= str_repeat('0', (8 - strlen($bits) % 8) % 8);

        $codewords = array_map(static fn(string $byte): int => (int) bindec($byte), str_split($bits, 8));
        for ($pad = 0xEC; count($codewords) < $capacity / 8; $pad ^= 0xEC ^ 0x11) {
            $codewords[] = $pad;
        }

        return $codewords;
    }

    /**
     * @param list<int> $data
     *
     * @return list<int> Data and error-correction codewords, interleaved by block.
     */
    private function interleave(array $data): array
    {
        $blocks = self::BLOCKS[$this->version];
        $eccLength = self::ECC[$this->version];
        $raw = intdiv(self::rawModules($this->version), 8);
        $shortBlocks = $blocks - $raw % $blocks;
        $shortLength = intdiv($raw, $blocks);
        $divisor = self::divisor($eccLength);

        $all = [];
        for ($i = 0, $k = 0; $i < $blocks; ++$i) {
            $length = $shortLength - $eccLength + ($i < $shortBlocks ? 0 : 1);
            $block = array_slice($data, $k, $length);
            $k += $length;
            $ecc = self::remainder($block, $divisor);
            if ($i < $shortBlocks) {
                $block[] = 0;
            }
            $all[] = array_merge($block, $ecc);
        }

        $result = [];
        $width = count($all[0]);
        for ($i = 0; $i < $width; ++$i) {
            foreach ($all as $j => $block) {
                if ($i !== $shortLength - $eccLength || $j >= $shortBlocks) {
                    $result[] = $block[$i];
                }
            }
        }

        return $result;
    }

    private function drawFunctionPatterns(): void
    {
        for ($i = 0; $i < $this->size; ++$i) {
            $this->set(6, $i, $i % 2 === 0);
            $this->set($i, 6, $i % 2 === 0);
        }

        foreach ([[3, 3], [$this->size - 4, 3], [3, $this->size - 4]] as [$x, $y]) {
            for ($dy = -4; $dy <= 4; ++$dy) {
                for ($dx = -4; $dx <= 4; ++$dx) {
                    $distance = max(abs($dx), abs($dy));
                    if ($x + $dx >= 0 && $x + $dx < $this->size && $y + $dy >= 0 && $y + $dy < $this->size) {
                        $this->set($x + $dx, $y + $dy, $distance !== 2 && $distance !== 4);
                    }
                }
            }
        }

        $positions = $this->alignmentPositions();
        $last = count($positions) - 1;
        foreach ($positions as $i => $px) {
            foreach ($positions as $j => $py) {
                if ($i === 0 && $j === 0 || $i === 0 && $j === $last || $i === $last && $j === 0) {
                    continue;
                }
                for ($dy = -2; $dy <= 2; ++$dy) {
                    for ($dx = -2; $dx <= 2; ++$dx) {
                        $this->set($px + $dx, $py + $dy, max(abs($dx), abs($dy)) !== 1);
                    }
                }
            }
        }

        $this->drawFormatBits(0);
        if ($this->version >= 7) {
            $remainder = $this->version;
            for ($i = 0; $i < 12; ++$i) {
                $remainder = ($remainder << 1) ^ (($remainder >> 11) * 0x1F25);
            }
            $bits = $this->version << 12 | $remainder;
            for ($i = 0; $i < 18; ++$i) {
                $a = $this->size - 11 + $i % 3;
                $b = intdiv($i, 3);
                $this->set($a, $b, ($bits >> $i & 1) === 1);
                $this->set($b, $a, ($bits >> $i & 1) === 1);
            }
        }
    }

    /** Format information: level M (00) and the mask, BCH-coded and masked with 0x5412. */
    private function drawFormatBits(int $mask): void
    {
        $data = $mask;
        $remainder = $data;
        for ($i = 0; $i < 10; ++$i) {
            $remainder = ($remainder << 1) ^ (($remainder >> 9) * 0x537);
        }
        $bits = ($data << 10 | $remainder) ^ 0x5412;
        $bit = static fn(int $i): bool => ($bits >> $i & 1) === 1;

        for ($i = 0; $i <= 5; ++$i) {
            $this->set(8, $i, $bit($i));
        }
        $this->set(8, 7, $bit(6));
        $this->set(8, 8, $bit(7));
        $this->set(7, 8, $bit(8));
        for ($i = 9; $i < 15; ++$i) {
            $this->set(14 - $i, 8, $bit($i));
        }
        for ($i = 0; $i < 8; ++$i) {
            $this->set($this->size - 1 - $i, 8, $bit($i));
        }
        for ($i = 8; $i < 15; ++$i) {
            $this->set(8, $this->size - 15 + $i, $bit($i));
        }
        $this->set(8, $this->size - 8, true);
    }

    /** @param list<int> $codewords */
    private function drawCodewords(array $codewords): void
    {
        $total = count($codewords) * 8;
        $i = 0;
        for ($right = $this->size - 1; $right >= 1; $right -= 2) {
            if ($right === 6) {
                $right = 5;
            }
            for ($vertical = 0; $vertical < $this->size; ++$vertical) {
                for ($j = 0; $j < 2; ++$j) {
                    $x = $right - $j;
                    $upward = (($right + 1) & 2) === 0;
                    $y = $upward ? $this->size - 1 - $vertical : $vertical;
                    if (!$this->function[$y][$x] && $i < $total) {
                        $this->modules[$y][$x] = ($codewords[$i >> 3] >> (7 - ($i & 7)) & 1) === 1;
                        ++$i;
                    }
                }
            }
        }
    }

    private function applyMask(int $mask): void
    {
        for ($y = 0; $y < $this->size; ++$y) {
            for ($x = 0; $x < $this->size; ++$x) {
                if ($this->function[$y][$x]) {
                    continue;
                }
                $invert = match ($mask) {
                    0 => ($x + $y) % 2 === 0,
                    1 => $y % 2 === 0,
                    2 => $x % 3 === 0,
                    3 => ($x + $y) % 3 === 0,
                    4 => (intdiv($x, 3) + intdiv($y, 2)) % 2 === 0,
                    5 => $x * $y % 2 + $x * $y % 3 === 0,
                    6 => ($x * $y % 2 + $x * $y % 3) % 2 === 0,
                    default => (($x + $y) % 2 + $x * $y % 3) % 2 === 0,
                };
                if ($invert) {
                    $this->modules[$y][$x] = !$this->modules[$y][$x];
                }
            }
        }
    }

    /** Penalty rules 1 (runs of five or more), 2 (2x2 blocks) and 4 (dark/light balance). */
    private function penalty(): int
    {
        $m = $this->modules;
        $penalty = 0;
        $dark = 0;
        for ($a = 0; $a < $this->size; ++$a) {
            $rowRun = 1;
            $columnRun = 1;
            for ($b = 0; $b < $this->size; ++$b) {
                $dark += $m[$a][$b] ? 1 : 0;
                if ($b === 0) {
                    continue;
                }
                $rowRun = $m[$a][$b] === $m[$a][$b - 1] ? $rowRun + 1 : 1;
                $columnRun = $m[$b][$a] === $m[$b - 1][$a] ? $columnRun + 1 : 1;
                $penalty += self::runPenalty($rowRun) + self::runPenalty($columnRun);
                if (
                    $a > 0 && $m[$a][$b] === $m[$a - 1][$b] && $m[$a][$b] === $m[$a][$b - 1]
                    && $m[$a][$b] === $m[$a - 1][$b - 1]
                ) {
                    $penalty += 3;
                }
            }
        }
        $total = $this->size * $this->size;

        return $penalty + 10 * (int) max(0, ceil(abs($dark * 20 - $total * 10) / $total) - 1);
    }

    /** Rule 1: 3 points when a run reaches five modules, 1 more for each module after that. */
    private static function runPenalty(int $run): int
    {
        return $run === 5 ? 3 : ($run > 5 ? 1 : 0);
    }

    private function set(int $x, int $y, bool $dark): void
    {
        $this->modules[$y][$x] = $dark;
        $this->function[$y][$x] = true;
    }

    /** @return list<int> */
    private function alignmentPositions(): array
    {
        if ($this->version === 1) {
            return [];
        }
        $count = intdiv($this->version, 7) + 2;
        $step = intdiv($this->version * 4 + $count * 2 + 1, $count * 2 - 2) * 2;
        $positions = [6];
        for ($i = $count - 1, $position = $this->size - 7; $i >= 1; --$i, $position -= $step) {
            $positions[$i] = $position;
        }
        ksort($positions);

        return array_values($positions);
    }

    private static function rawModules(int $version): int
    {
        $result = (16 * $version + 128) * $version + 64;
        if ($version >= 2) {
            $count = intdiv($version, 7) + 2;
            $result -= (25 * $count - 10) * $count - 55;
            if ($version >= 7) {
                $result -= 36;
            }
        }

        return $result;
    }

    private static function dataCodewords(int $version): int
    {
        return intdiv(self::rawModules($version), 8) - self::ECC[$version] * self::BLOCKS[$version];
    }

    /** @return list<int> Reed-Solomon generator polynomial of the given degree over GF(2^8)/0x11D. */
    private static function divisor(int $degree): array
    {
        $result = array_fill(0, $degree, 0);
        $result[$degree - 1] = 1;
        $root = 1;
        for ($i = 0; $i < $degree; ++$i) {
            for ($j = 0; $j < $degree; ++$j) {
                $result[$j] = self::multiply($result[$j], $root);
                if ($j + 1 < $degree) {
                    $result[$j] ^= $result[$j + 1];
                }
            }
            $root = self::multiply($root, 0x02);
        }

        return $result;
    }

    /**
     * @param list<int> $data
     * @param list<int> $divisor
     *
     * @return list<int>
     */
    private static function remainder(array $data, array $divisor): array
    {
        $result = array_fill(0, count($divisor), 0);
        foreach ($data as $byte) {
            $factor = $byte ^ array_shift($result);
            $result[] = 0;
            foreach ($divisor as $i => $coefficient) {
                $result[$i] ^= self::multiply($coefficient, $factor);
            }
        }

        return $result;
    }

    private static function multiply(int $x, int $y): int
    {
        $z = 0;
        for ($i = 7; $i >= 0; --$i) {
            $z = ($z << 1) ^ (($z >> 7) * 0x11D);
            $z ^= (($y >> $i) & 1) * $x;
        }

        return $z & 0xFF;
    }
}
