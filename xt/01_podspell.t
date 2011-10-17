use Test::More;
eval q{ use Test::Spelling };
plan skip_all => "Test::Spelling is not installed." if $@;
add_stopwords(map { split /[\s\:\-]/ } <DATA>);
$ENV{LANG} = 'C';
all_pod_files_spelling_ok('lib');
__DATA__
Tokuhiro Matsuno
Amon2::Plugin::Auth
tokuhirom
AAJKLFJEF
GMAIL
COM
Tatsuhiko
Miyagawa
Kazuhiro
Osawa
lestrrat
typester
cho45
charsbar
coji
clouder
gunyarakun
hio_d
hirose31
ikebe
kan
kazeburo
daisuke
maki
TODO
API
URL
URI
db
plugins
callback
auth
OAuth
Facebook
mixi
twitter
Github
Str
APIs
github
loctouch
LocTouch
facebook
SNS
