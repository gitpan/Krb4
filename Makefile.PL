use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Authen::Krb4',
    'VERSION_FROM' => 'Krb4.pm',
    'LIBS'	=> ['-L/usr/local/krb4/lib -lkrb -ldes'],
    'DEFINE'	=> '',
    'INC'	=> '-I/usr/local/krb4/include'
);
