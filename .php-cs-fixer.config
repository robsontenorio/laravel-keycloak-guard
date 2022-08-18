<?php

$finder = PhpCsFixer\Finder::create()
	->notPath('.ebextensions')
	->notPath('.elasticbeanstalk')
	->notPath('docs')
	->notPath('public')
	->notPath('resources')
	->notPath('storage')
	->in(__DIR__)
	->name('*.php')
	->notName('*.blade.php')
	->ignoreDotFiles(true)
	->ignoreVCS(true);

$config = new PhpCsFixer\Config();

return $config
	->setCacheFile(__DIR__ . '/vendor/.php_cs.cache')
	->setRules([
		'@PSR12'          => true,
		'@PHP80Migration' => true,
		'binary_operator_spaces' => [
			'operators' => [
				'=>' => 'align_single_space_minimal'
			]
		],
		'blank_line_before_statement'                 => true,
		'cast_spaces'                                 => ['space' => 'single'],
		'no_blank_lines_after_class_opening'          => true,
		'no_blank_lines_after_phpdoc'                 => true,
		'no_closing_tag'                              => true,
		'no_empty_phpdoc'                             => true,
		'no_leading_import_slash'                     => true,
		'no_leading_namespace_whitespace'             => true,
		'no_multiline_whitespace_around_double_arrow' => true,
		'no_short_bool_cast'                          => true,
		'no_singleline_whitespace_before_semicolons'  => true,
		'no_spaces_after_function_name'               => true,
		'no_spaces_inside_parenthesis'                => true,
		'no_superfluous_phpdoc_tags'                  => ['allow_mixed' => true],
		'no_trailing_comma_in_list_call'              => true,
		'no_trailing_comma_in_singleline_array'       => true,
		'no_trailing_whitespace'                      => true,
		'no_trailing_whitespace_in_comment'           => true,
		'no_unused_imports'                           => true,
		'no_useless_return'                           => true,
		'no_whitespace_before_comma_in_array'         => true,
		'ordered_imports'                             => ['sort_algorithm' => 'alpha'],
		'phpdoc_align'                                => true,
		'phpdoc_indent'                               => true,
		'phpdoc_line_span'                            => ['method' => 'single', 'const' => 'single', 'property' => 'single'],
		'phpdoc_no_access'                            => true,
		'phpdoc_no_package'                           => true,
		'phpdoc_order'                                => true,
		'phpdoc_scalar'                               => true,
		'phpdoc_separation'                           => true,
		'phpdoc_summary'                              => true,
		'phpdoc_to_comment'                           => false,
		'phpdoc_trim'                                 => true,
		'phpdoc_types'                                => true,
		'phpdoc_var_without_name'                     => true,
		'types_spaces'                                => ['space' => 'none']
	])
	->setFinder($finder);
