use inc::Module::Install;
use Module::Install::AuthorTests;

name       'Amon2-Auth-Site-Hatena';
all_from   'lib/Amon2/Auth/Site/Hatena.pm';

requires   'Amon2::Auth' => '0.01';
requires   'JSON'        => '2.53';
requires   'Mouse'       => '0.97';
requires   'OAuth::Lite' => '1.31';

recommends 'HTTP::BrowserDetect' => '1.33';
recommends 'HTTP::MobileAgent'   => '0';

tests 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t';
test_requires 'Test::More' => 0.96; # done_testing, subtest
author_tests('xt');
WriteAll;
