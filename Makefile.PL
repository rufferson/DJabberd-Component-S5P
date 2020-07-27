#!/usr/bin/perl
use 5.008;
use ExtUtils::MakeMaker;
WriteMakefile(
	NAME => 'DJabberd::Component::S5P',
	VERSION_FROM => 'lib/DJabberd/Component/S5P.pm',
	ABSTRACT_FROM => 'lib/DJabberd/Component/S5P.pm',
	PREREQ_PM => {
		'DJabberd' => '0.86',
	},
	AUTHOR => 'Ruslan N. Marchenko <me@ruff.mobi>',
);
