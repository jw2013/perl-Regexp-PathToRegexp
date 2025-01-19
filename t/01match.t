#!/usr/bin/perl

use v5.14;
use warnings;

use Test::More;
use Data::Dumper;

use Regexp::PathToRegexp qw( match );

{
    my $match = "/foo/:bar";
    my $path = "/test/route";
    my $result = undef;
    *fn1 = match($match);
    is_deeply(fn1($path), $result, "match(\"".quotemeta($match)."\") for \"".quotemeta($path)."\"");
}

{
    my $match = "/:foo{/:bar}";
    my $path = "/test/";
    my $result = {
        'path' => '/test/',
        'params' => {
            'foo' => 'test',
        }
    };
    *fn2 = match($match);
    is_deeply(fn2($path), $result, "match(\"".quotemeta($match)."\") for \"".quotemeta($path)."\"");
}

{
    my $match = "/:foo{/:\"Some random field\"}";
    my $path = "/test/route";
    my $result = {
        'path' => '/test/route',
        'params' => {
            'foo' => 'test',
            'Some random field' => 'route',
        }
    };
    *fn3 = match($match);
    is_deeply(fn3($path), $result, "match(\"".quotemeta($match)."\") for \"".quotemeta($path)."\"");
}
 
{
    my $match = "/:foo{/*bar}";
    my $path = "/test/route/sub";
    my $result = {
        'path' => '/test/route/sub',
        'params' => {
            'foo' => 'test',
            'bar' => ['route','sub']
        }
    };
    *fn4 = match($match);
    is_deeply(fn4($path), $result, "match(\"".quotemeta($match)."\") for \"".quotemeta($path)."\"");
}



done_testing;
