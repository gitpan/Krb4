use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Krb4',
    'VERSION_FROM' => 'Krb4.pm',
    'LIBS'	=> ['-L/usr/itd/packages/k/kerberos-4/sun4x_55/lib -lkrb -ldes'],
    'DEFINE'	=> '',
    'INC'	=> '-I/usr/itd/packages/k/kerberos-4/sun4x_55/include'
);
