<?php

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

$rules = [
    '@PSR12' => true,
    'no_unused_imports' => true,
    'braces' => true,
    'array_indentation' => true,
    'whitespace_after_comma_in_array' => true,
    'binary_operator_spaces' => true,
    'no_extra_blank_lines' => true,
    'method_chaining_indentation' => true,
    'concat_space' => [
        'spacing' => 'none',
    ],
    'ordered_imports' => [
        'sort_algorithm' =>
        'alpha',
    ],
    'class_attributes_separation' => [
        'elements' => [
            'method' => 'one',
        ],
    ],
    'blank_line_before_statement' => [
        'statements' => [
            'if',
            'break',
            'continue',
            'return',
            'throw',
            'try'
        ],
    ],
];

$finder = Finder::create()
    ->in([
        __DIR__ . '/src',
        __DIR__ . '/config',        
        __DIR__ . '/tests',
    ])
    ->name('*.php')
    ->notName('*.blade.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true)
;

return (new Config())
    ->setFinder($finder)
    ->setRules($rules)
    ->setRiskyAllowed(true)
    ->setUsingCache(true);
