package Regexp::PathToRegexp;

use utf8;
use Carp;
use warnings;
use Data::Dumper;

use strict;

use Exporter 'import';
our @EXPORT_OK = qw( match path_to_regexp compile parse stringify );  # symbols to export on request

use constant DEFAULT_DELIMITER => "/";
use constant NOOP_VALUE => sub { return @_ if wantarray; return shift @_; };
use constant ID_START => qr/^[\$_\p{ID_Start}]$/u;
use constant ID_CONTINUE => qr/^[\$\u200c\u200d\p{ID_Continue}]$/u;
use constant DEBUG_URL => "https://git.new/pathToRegexpError";
use constant SIMPLE_TOKENS => {
    # Groups.
    "{"=> "{",
    "}"=> "}",
    # Reserved.
    "("=> "(",
    ")"=> ")",
    "["=> "[",
    "]"=> "]",
    "+"=> "+",
    "?"=> "?",
    "!"=> "!",
};


=encoding utf8

=head1 NAME

C<Regexp::PathToRegexp> - Turn a path string such as C</user/:name> into a regular expression.

=head1 SYNOPSIS

 use Regexp::PathToRegexp qw(
    match
    path_to_regexp
    compile
    parse
    stringify
 );
 
 *fn = match("/:foo/:bar");
 fn("/test/route");
 # $_ = { path => '/test/route', params => { foo => 'test', bar => 'route' } }

 my $fn = match("/file/{:name}{.:ext}");
 &$fn("/file/test.jpg");
 # $_ = { path => '/file/test.jpg', params => { name => 'test', ext => 'jpg' } }


=head1 DESCRIPTION

This is a port of the excellent Node.js package C<path-to-regexp> to the Perl programming language.
The C<path-to-regexp> package is a core component of the widely used C<express.js> framework. All kudos go to B<Blake Embrey> and the other contributors.

This Perl package is currently based on the version C<8.2> of the original Node.js package, which has been completely rewamped and hardened against ReDoS attacks.

More information about ReDoS attacks can be found here:

=over

=item * L<https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS>

=item * L<https://blakeembrey.com/posts/2024-09-web-redos/>

=back

=head1 PARAMETERS

Parameters match arbitrary strings in a path by matching up to the end of the segment, or up to any proceeding tokens. They are defined by prefixing a colon to the parameter name (C<:foo>). Parameter names can use any valid JavaScript identifier, or be double quoted to use other characters (C<:"param-name">).

 *fn = match("/:foo/:bar");

 fn("/test/route");
 # $_ = { path => '/test/route', params => { foo => 'test', bar => 'route' } }

=head1 WILDCARD

Wildcard parameters match one or more characters across multiple segments. They are defined the same way as regular parameters, but are prefixed with an asterisk (C<*foo>).

 *fn = match("/*splat");

 fn("/bar/baz");
 # $_ = { path => '/bar/baz', params => { splat => [ 'bar', 'baz' ] } }

=head1 OPTIONAL

Braces can be used to define parts of the path that are optional.

 *fn = match("/users{/:id}/delete");
 
 fn("/users/delete");
 # $_ = { path => '/users/delete', params => {} }
 
 fn("/users/123/delete");
 # $_ = { path => '/users/123/delete', params => { id => '123' } }

=head1 METHODS

=cut

sub escape_text {
    my $str = shift;
    $str =~ s/[{}()\[\]+?!:*]/\\$&/g;
    return $str;
}


sub escape {
    my $str = shift;
    $str =~ s/[.+*?^\${}()\[\]|\/\\]/\\$&/g;
    return $str;
}


sub lexer {
    my $str = shift;
    my @chars = split //, $str;
    my $i = 0;

    my $name = sub {
        no warnings;       # $chars[++$i] might be undef
        my $value = "";
        if ( $chars[++$i] =~ ID_START ) {
            $value .= $chars[$i];
            while ( $chars[++$i] =~ ID_CONTINUE ) {
                $value .= $chars[$i];
            }
        }
        elsif ( $chars[$i] eq '"' ) {
            my $pos = $i;
            while ( $i < scalar @chars ) {
                if ( $chars[++$i] eq '"' ) {
                    $i++;
                    $pos = 0;
                    last;
                }
                elsif ( $chars[$i] eq "\\" ) {
                    $value .= $chars[++$i];
                }
                else {
                    $value .= $chars[$i];
                }
            }
            if ( $pos ) {
                croak "Unterminated quote at $pos: ".DEBUG_URL;
            }
        }
        if ( !length $value ) {
            croak "Missing parameter name at $i: ".DEBUG_URL;
        }
        return $value;
    };

    return sub {
        while ( $i < scalar(@chars) ) {
            my $value = $chars[$i];
            my $type = SIMPLE_TOKENS->{$value} if exists SIMPLE_TOKENS->{$value};
            if ( $type ) {
                return { type => $type, index => $i++, value => $value };
            }
            elsif ( $value eq "\\" ) {
                return { type => "ESCAPED", index => $i++, value => $chars[$i++] };
            }
            elsif ( $value eq ":" ) {
                $value = &$name();
                return { type => "PARAM", index => $i, value => $value };
            }
            elsif ( $value eq "*" ) {
                $value = &$name();
                return { type => "WILDCARD", index => $i, value => $value };
            }
            else {
                return { type => "CHAR", index => $i, value => $chars[$i++] };
            }
        }
        return { type => "END", index => $i, value => "" };
    }
}



sub decode_uri_component {
    my $str = shift;
    $str =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
    return $str;
}

sub encode_uri_component {
    my $str = shift;
    $str =~ s/([^^A-Za-z0-9\-_.!~*'()])/ sprintf "%%%02X", ord $1 /eg;
    return $str;
}


=head2 match

 *fn = match("/foo/:bar");

The C<match> function returns a function for matching strings against a path:

=over

=item B<path> String or array of strings.

=item B<options> I<(optional)> (Extends path_to_regexp options)

=over

=item B<decode> Function for decoding strings to params, or C<undef> to disable all processing. (default: C<decodeURIComponent>)

=back

=back

B<Please note:> C<Regexp::PathToRegexp> is intended for ordered data (e.g. paths, hosts). It can not handle arbitrarily ordered data (e.g. query strings, URL fragments, JSON, etc).

=cut


sub match($;$) {
    my $path = shift;
    my $options = shift || {};
    %$options = ( decode => \&decode_uri_component, delimiter => DEFAULT_DELIMITER, %$options );
    my $decode = $options->{decode};
    my $delimiter = $options->{ delimiter };
    my ( $regexp, $keys ) = path_to_regexp($path, $options);
    my %decoders = map{ $_ =>
        ( !$decode ) ? NOOP_VALUE : 
            ( $_->{type} eq "param" ) ? $decode :
                sub { return [map { &$decode($_) } split $delimiter, $_[0]] }
    } @$keys;

    return sub {
        my $input = shift;
        my $m = $input =~ $regexp;
        if ( !$m ) {
            return undef;
        }
        my $path = $&;
        my $params = {};


        for ( my $i = 1; $i < scalar(@-); $i++ ) {
            next if !defined $-[$i];
            my $key = $keys->[$i-1];
            my $decoder = $decoders{$key};
            $params->{$key->{name}} = &$decoder(substr $input, $-[$i], $+[$i]-$-[$i]);
        }

        return { path => $path, params => $params };
    }
}


=head2 path_to_regexp

 my ( $regexp, $keys ) = path_to_regexp("/foo/:bar");

The C<path_to_regexp> function returns the C<regexp> for matching strings against paths,
and an array of C<keys> for understanding the C<RegExp> matches.

=over

=item B<path> String or array of strings.

=item B<options> I<(optional)> (See parse for more options)

=over

=item B<sensitive> Regexp will be case sensitive. (default: C<0>)

=item B<end> Validate the match reaches the end of the string. (default: C<1>)

=item B<delimiter> The default delimiter for segments, e.g. C<[^/]> for C<:named> parameters. (default: C<'/'>)

=item B<trailing> Allows optional trailing delimiter to match. (default: C<1>)

=back

=back

=cut


sub path_to_regexp($;$) {
    my $path = shift;
    my $options = shift || {};
    %$options = ( delimiter => DEFAULT_DELIMITER, end => 1, sensitive => 0, trailing => 1, %$options );
    my $delimiter = $options->{ delimiter };
    my $end = $options->{ end };
    my $sensitive = $options->{ sensitive };
    my $trailing = $options->{ trailing };

    my $keys = [];
    my $sources = [];
    my $flags = $sensitive ? "" : "i";

    my @paths = (ref($path) eq "ARRAY")? @$path : ($path);

    my @items = map { ($_->isa("Regexp::PathToRegexp::TokenData"))? $_ : parse($_, $options) } @paths;

    foreach my $tokens ( map { $_->{tokens} } @items ) {
        foreach my $seq ( flatten($tokens, 0, []) ) {
            my $regexp = sequence_to_regexp($seq, $delimiter, $keys);
            push @$sources, $regexp;
        }
    }
    my $pattern = '^(?:'.join("|", @$sources).')';
    if ( $trailing ) {
        $pattern .= '(?:'.escape($delimiter).'$)?';
    }
    $pattern .= $end ? '$' : '(?='.escape($delimiter).'|$)';
    my $regexp = ($sensitive) ? qr/$pattern/ : qr/$pattern/i;
    return $regexp, $keys;
}


sub flatten {
    my ( $tokens, $index, $init ) = @_;

    if ( $index == scalar(@$tokens) ) {
        return $init;
    }
    my $token = $tokens->[$index];
    my @seq = ();
    if ( $token->{type} eq "group" ) {
        my $fork = [@$init];
        foreach my $seq ( flatten($token->{tokens}, 0, $fork) ) {
            push @seq, flatten( $tokens, $index + 1, $seq );
        }
    }
    else {
        push @$init, $token;
    }
    return @seq, flatten($tokens, $index + 1, $init );
}


sub sequence_to_regexp {
    my ( $tokens, $delimiter, $keys ) = @_;
    my $result = "";
    my $backtrack = "";
    my $isSafeSegmentParam = 1;
    for ( my $i = 0; $i < scalar(@$tokens); $i++ ) {
        my $token = $tokens->[$i];
        if ( $token->{type} eq "text" ) {
            $result .= escape($token->{value});
            $backtrack .= $token->{value};
            $isSafeSegmentParam || ($isSafeSegmentParam = (index($token->{value}, $delimiter) > 0));
            next;
        }
        if ( $token->{type} eq "param" || $token->{type} eq "wildcard" ) {
            if ( !$isSafeSegmentParam && !$backtrack ) {
                croak "Missing text after $token->{name}: ".DEBUG_URL;
            }
            if ( $token->{type} eq "param" ) {
                $result .= '('.negate($delimiter, $isSafeSegmentParam ? "" : $backtrack).'+)';
            }
            else {
                $result .= '([\\s\\S]+)';
            }
            push @$keys, $token;
            $backtrack = "";
            $isSafeSegmentParam = 0;
            next;
        }
    }
    return $result;
}


sub negate {
    my ( $delimiter, $backtrack ) = @_;
    if ( length($backtrack) < 2 ) {
        if ( length($delimiter) < 2 ) {
            return '[^'.escape($delimiter.$backtrack).']';
        }
        return '(?:(?!'.escape($delimiter).')[^'.escape($backtrack).'])';
    }
    if ( length($delimiter) < 2 ) {
        return '(?:(?!'.escape($backtrack).')[^'.escape($delimiter).'])';
    }
    return '(?:(?!'.escape($backtrack).'|'.escape($delimiter).')[\\s\\S])';
}



=head2 compile ("Reverse" Path-To-RegExp)

 *toPath = compile("/user/:id");
 
 toPath({ id => "name" }); # $_ = "/user/name"
 toPath({ id => "café" }); # $_ = "/user/caf%C3%A9"
 
 *toPathRepeated = compile("/*segment");
 
 toPathRepeated({ segment => ["foo"] }); # $_ = "/foo"
 toPathRepeated({ segment => ["a", "b", "c"] }); # $_ = "/a/b/c"

 # When disabling C<encode>, you need to make sure inputs are encoded correctly. No arrays are accepted.
 *toPathRaw = compile("/user/:id", { encode => 0 });
 
 toPathRaw({ id => "%3A%2F" }); # $_ = "/user/%3A%2F"

The C<compile> function will return a function for transforming parameters into a valid path:

=over

=item B<path> A string.

=item B<options> I<(optional)> (See parse for more options)

=over

=item B<delimiter> The default delimiter for segments, e.g. C<[^/]> for C<:named> parameters. (default: C<'/'>)

=item B<encode> Function for encoding input strings for output into the path, or C<undef> to disable entirely. (default: C<encodeURIComponent>)

=back

=back

=cut



sub compile($;$) {
    my $path = shift;
    my $options = shift || {};
    %$options = ( encode => \&encode_uri_component, delimiter => DEFAULT_DELIMITER, %$options );
    my $encode = $options->{encode};
    my $delimiter = $options->{delimiter};
    my $data = $path->isa("Regexp::PathToRegexp::TokenData") ? $path : parse($path, $options);
    my $fn = tokens_to_function($data->{tokens}, $delimiter, $encode);
    return sub {
        my $data = shift;
        my ( $path, @missing ) = &$fn($data);
        if ( @missing ) {
            croak("Missing parameters: ", join(", ", @missing));
        }
        return $path;
    }
}


sub tokens_to_function {
    my ( $tokens, $delimiter, $encode ) = @_;
    my @encoders = map { token_to_function($_, $delimiter, $encode) } @$tokens;
    return sub {
        my $data = shift;
        my @result = ("");
        foreach my $encoder ( @encoders ) {
            my ( $value, @extras ) = &$encoder($data);
            $result[0] .= $value;
            push @result, @extras;
        }
        return @result;
    }
}


sub token_to_function {
    my ( $token, $delimiter, $encode ) = @_;
    if ( $token->{type} eq "text" ) {
        return sub { return $token->{value} };
    }
    if ( $token->{type} eq "group" ) {
        my $fn = tokens_to_function($token->{tokens}, $delimiter, $encode);
        return sub {
            my $data = shift;
            my ( $value, @missing ) = &$fn($data);
            if ( !@missing ) {
                return $value;
            }
            return "";
        };
    }
    my $encodeValue = $encode || NOOP_VALUE;
    if ( ($token->{type} eq "wildcard") && $encode ) {
        return sub {
            no warnings;
            my $data = shift;
            my $value = $data->{$token->{name}};
            if ( !defined $value ) {
                return "", $token->{name};
            }
            if ( (!ref $value) || (ref($value) ne "ARRAY") ) {
                croak "Expected $token->{name} to be a non-empty array";
            }
            my $index = -1;
            return join $delimiter, map {
                $index++;
                ref $_? croak "Expected $token->{name}/$index to be a string" : &$encodeValue($_)
            } @$value;
        };
    }
    return sub {
        no warnings;
        my $data = shift;
        my $value = $data->{$token->{name}};
        if ( !defined $value ) {
            return "", $token->{name};
        }
        if ( ref $value ) {
            croak "Expected $token->{name} to be a scalar";
        }
        return &$encodeValue($value);
    }
}


=head2 stringify

 my $data = Regexp::PathToRegexp::TokenData->new([
     { type => 'text', value => "/" },
     { type => 'param', name => "foo" },
 ]);
 my $path = stringify($data);    # $path = "/:foo"

The C<stringify> transform C<TokenData> (a sequence of tokens) back into a Path-to-RegExp string.

=over

=item B<data> A Regexp::PathToRegexp::TokenData instance

=back

=cut



sub stringify($) {
    my $data = shift;

    sub stringifyToken {
        my ( $token, $index, $tokens ) = @_;
        if ( $token->{type} eq "text" ) {
            return escape_text($token->{value});
        }
        if ( $token->{type} eq "group" ) {
            my $index = -1;
            my $token_tokens = $token->{tokens};
            return '{'.join("", map { $index++; stringifyToken($_, $index, $token_tokens) } @{$token_tokens} ).'}';
        }
        my $isSafe = isNameSafe($token->{name}) && isNextNameSafe($tokens->[$index + 1]);
        my $key = $isSafe ? $token->{name} : stringify_name($token->{name});
        if ( $token->{type} eq "param" ) {
            return ":$key";
        }
        if ( $token->{type} eq "wildcard" ) {
            return "*$key";
        }
        croak "Unexpected token: $token";
    };

    my $index = -1;
    my $tokens = $data->{tokens};
    return join("", map { $index++; stringifyToken($_, $index, $tokens) } @{$tokens} );
}



=head2 parse

 my $data = parse("/user/:id"); # ref($data) eq "Regexp::PathToRegexp::TokenData"
 my $path = stringify($data);   # $path = "/user/:id"

The C<parse> function accepts a string and returns an instance of C<Regexp::PathToRegexp::TokenData>, the set of tokens and other metadata parsed from the input string.
=over

=item B<path> A string.

=item B<options> I<(optional)>

=over

=item B<encodePath> A function for encoding input strings. (default: no encoding)

=back

=back

=cut



sub parse($;$) {
    my $str = shift;
    my $options = shift || {};
    %$options = ( encodePath => NOOP_VALUE, %$options );
    my $encodePath = $options->{ encodePath };
    my $it = Regexp::PathToRegexp::Iter->new(lexer($str));

    my $consume;
    $consume = sub {
        my $endType = shift;
        my $tokens = [];
        while ( 1 ) {
            my $path = $it->text();
            if ( length($path) ) {
                push @$tokens, { type => "text", value => &$encodePath($path) };
            }
            my $param = $it->tryConsume("PARAM");
            if ( defined $param ) {
                push @$tokens, {
                    type => "param",
                    name => $param
                };
                next;
            }
            my $wildcard = $it->tryConsume("WILDCARD");
            if ( defined $wildcard ) {
                push @$tokens, {
                    type => "wildcard",
                    name => $wildcard
                };
                next;
            }
            my $open = $it->tryConsume("{");
            if ( defined $open ) {
                push @$tokens, {
                    type => "group",
                    tokens => &$consume("}")
                };
                next;
            }
            $it->consume($endType);
            return $tokens;
        }
    };
    my $tokens = &$consume("END");
    return new Regexp::PathToRegexp::TokenData($tokens);
}



sub isNameSafe {
    my ( $name ) = @_;
    my ( $first, @rest ) = split //, $name;
    if ( $first !~ ID_START ) {
        return 0;
    }
    map { return 0 if $_ !~ ID_CONTINUE } @rest;
    return 1;
}

sub isNextNameSafe {
    my $token = shift;
    if ( (!$token) || ($token->{type} ne "text") ) {
        return 1;
    }

    return !(substr($token->{value}, 0, 1) =~ ID_CONTINUE);
}

sub stringify_name {
    my $name = shift;
    $name =~ s/(['"\\])/\\$1/g;
    return '"'.$name.'"';
}




package Regexp::PathToRegexp::Iter;

use strict;

use Carp;

sub new {
    my ( $package, $tokens ) = @_;
    my $self = bless {}, $package;
    $self->{tokens} = $tokens;
    $self->{_peek} = undef;
    return $self;
}

sub peek {
    my ( $self ) = @_;
    if ( !$self->{_peek} ) {
        my $next = $self->{tokens}();
        $self->{_peek} = $next;
    }
    return $self->{_peek};
}

sub tryConsume {
    my ( $self, $type ) = @_;
    my $token = $self->peek();

    if ( $token->{type} ne $type ) {
        return undef;
    }

    $self->{_peek} = undef;
    return $token->{value};
}

sub consume {
    my ( $self, $type ) = @_;
    my $value = $self->tryConsume($type);
    if ( defined $value ) {
        return $value;
    }

    my $next =  $self->{tokens}();
    croak "Unexpected $next->{type} at $next->{index}, expected $type: ".Regexp::PathToRegexp::DEBUG_URL;
}

sub text {
    my ( $self ) = @_;
    my $result = "";
    my $value;
    while ( defined ($value = $self->tryConsume("CHAR") || $self->tryConsume("ESCAPED")) ) {
        $result .= $value;
    }
    return $result;
}


package Regexp::PathToRegexp::TokenData;

use strict;

sub new {
    my ( $package, $tokens ) = @_;
    my $self = bless {}, $package;
    $self->{tokens} = $tokens;
    return $self;
}


=head1 AUTHOR

Jens Wagner <jens@wagner2013.de>

Based on the C<path-to-regexp> node package:
L<https://github.com/pillarjs/path-to-regexp>

=head1 COPYRIGHT AND LICENSE

(c)2025 Jens Wagner

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut


0x55AA;
