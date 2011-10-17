use strict;
use warnings;
use utf8;

package Amon2::Auth::Site::Hatena;
use Mouse;

use JSON;
use Amon2::Auth;
use OAuth::Lite::Consumer;

our $VERSION = '0.01';

sub moniker { 'hatena' }

has consumer_key => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has consumer_secret => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has scope => (
    is      => 'ro',
    isa     => 'ArrayRef',
    default => sub { +[qw(read_public)] },
);

has user_info => (
    is      => 'rw',
    isa     => 'Bool',
    default => 1,
);

has ua => (
    is      => 'ro',
    isa     => 'OAuth::Lite::Consumer',
    lazy    => 1,
    default => sub {
        OAuth::Lite::Consumer->new(
            consumer_key       => $_[0]->consumer_key,
            consumer_secret    => $_[0]->consumer_secret,
            site               => $_[0]->site,
            request_token_path => $_[0]->request_token_path,
            access_token_path  => $_[0]->access_token_path,
            authorize_path     => $_[0]->authorize_path,
        );
    },
);

has site => (
    is      => 'ro',
    isa     => 'Str',
    default => 'https://www.hatena.com',
);

has request_token_path => (
    is      => 'ro',
    isa     => 'Str',
    default => '/oauth/initiate',
);

has access_token_path => (
    is      => 'ro',
    isa     => 'Str',
    default => '/oauth/token',
);

has authorize_path => (
    is      => 'ro',
    isa     => 'Str',
    default => 'https://www.hatena.ne.jp/oauth/authorize',
);

has user_info_url => (
    is      => 'ro',
    isa     => 'Str',
    default => 'http://n.hatena.com/applications/my.json',
);

has redirect_url => (
    is  => 'ro',
    isa => 'Str',
);

sub auth_uri {
    my ($self, $c, $callback_uri) = @_;

    my $request_token = $self->ua->get_request_token(
        callback_url => $callback_uri || $self->redirect_url,
        scope        => join(',', @{$self->scope}),
    ) or die $self->ua->errstr;

    $c->session->set(auth_hatena => $request_token);
    $self->ua->url_to_authorize(token => $request_token);
}

sub callback {
    my ($self, $c, $callback) = @_;
    my $error = $callback->{on_error};

    my $verifier = $c->req->param('oauth_verifier')
        or return $error->("Cannot get a `oauth_verifier' parameter");
    my $token = $c->session->get('auth_hatena')
        or return $error->("Request tokens are required");
    my $access_token = $self->ua->get_access_token(
        token    => $token,
        verifier => $verifier,
    ) or return $error->($self->ua->errstr);

    my @args = ($access_token->token, $access_token->secret);

    if ($self->user_info) {
        my $res  = $self->ua->get($self->user_info_url);
        return $error->($self->ua->errstr) if $res->is_error;

        my $data = decode_json($res->decoded_content);
        push @args, $data;
    }

    $callback->{on_finished}->(@args);
}

1;

__END__

=head1 NAME

Amon2::Auth::Site::Hatena - Hatena Auth integration for Amon2

=head1 SYNOPSIS

    __PACKAGE__->load_plugin('Web::Auth', {
        module   => 'Hatena',
        on_error => sub {
            my ($c, $error_message) = @_;
            ...
        },
        on_finished => sub {
            my ($c, $token, $token_secret, $user) = @_;

            my $name  = $user->{url_name};     #=> eg. antipop (id)
            my $nick  = $user->{display_name}; #=> eg. kentaro (nick)
            my $image = $user->{profile_image_url};

            $c->session->set(hatena => {
                user         => $user,
                token        => $token,
                token_secret => $token_secret,
            });

            $c->redirect('/');
        },
    });

=head1 DESCRIPTION

This is a Hatena authentication module for Amon2. You can call a
Hatena APIs with this module.

=head1 ATTRIBUTES

=over 4

=item consumer_key

=item comsumer_secret

=item scope

API scope in ArrayRef.

=item user_info(Default: true)

Fetch user information after authenticate?

=item ua(instance of OAuth::Lite)

You can replace instance of L<OAuth::Lite>.

=back

=head1 METHODS

=over 4

=item $auth->auth_uri($c:Amon2::Web, $callback_uri : Str) : Str

Get a authenticate URI.

=item $auth->callback($c:Amon2::Web, $callback:HashRef) : Plack::Response

Process the authentication callback dispatching.

C<< $callback >> MUST have two keys.

=over 4

=item on_error

on_error callback function is called if an error was occurred.

The arguments are following:

    sub {
        my ($c, $error_message) = @_;
        ...
    }

=item on_finished

on_finished callback function is called if an authentication was finished.

The arguments are following:

    sub {
        my ($c, $access_token, $access_token_secret, $user) = @_;
        ...
    }

C<< $user >> contains user information. This code contains a information like L<https://api.github.com/users/dankogai>.

If you set C<< $auth->user_info >> as false value, authentication engine does not pass C<< $user >>.

=back

=back
