/*
 * Kerberos 4 extensions for Perl 5
 * Author: Jeff Horwitz <jhorwitz@umich.edu>
 *
 * Copyright (c) 1997 Jeff Horwitz (jhorwitz@umich.edu).  All rights reserved.
 * This module is free software; you can redistribute it and/or modify it under   
 * the same terms as Perl itself.
 *
 * Radix routines courtesy of Dug Song <dugsong@umich.edu>
 *
 */

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <netdb.h>
#include <netinet/in.h>
#include <krb.h>
#include <des.h>
#ifdef __cplusplus
}
#endif

#define ENC_HEADER_SZ 32

typedef unsigned char my_u_char;
typedef unsigned int my_u_int32_t;
typedef unsigned short my_u_short;

typedef KTEXT Krb4__Ticket;
typedef CREDENTIALS * Krb4__Creds;
typedef AUTH_DAT * Krb4__AuthDat;
typedef des_key_schedule * Krb4__KeySchedule;

#define GETSHORT(s, cp) { \
	register my_u_char *t_cp = (my_u_char*)(cp); \
	(s) = (((my_u_short)t_cp[0]) << 8) \
	    | (((my_u_short)t_cp[1])) \
	    ; \
	(cp) += 2; \
}

#define GETLONG(l, cp) { \
	register my_u_char *t_cp = (my_u_char*)(cp); \
	(l) = (((my_u_int32_t)t_cp[0]) << 24) \
	    | (((my_u_int32_t)t_cp[1]) << 16) \
	    | (((my_u_int32_t)t_cp[2]) << 8) \
	    | (((my_u_int32_t)t_cp[3])) \
	    ; \
	(cp) += 4; \
}

#define PUTSHORT(s, cp) { \
	register my_u_short t_s = (my_u_short)(s); \
	register my_u_char *t_cp = (my_u_char*)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += 2; \
}

/*
 * Warning: PUTLONG --no-longer-- destroys its first argument.  if you
 * were depending on this "feature", you will lose.
 */
#define PUTLONG(l, cp) { \
	register my_u_int32_t t_l = (my_u_int32_t)(l); \
	register my_u_char *t_cp = (my_u_char*)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += 4; \
}

static char *radixN =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char _pad = '=';

void seterror(int error)
{	SV * errorsv;
	errorsv=perl_get_sv("Krb4::error",TRUE|0x04);
	sv_setiv(errorsv,error);
}

radix_encode(inbuf, outbuf, len, decode)
     unsigned char inbuf[], outbuf[];
     int *len, decode;
{
  int i,j,D;
  char *p;
  unsigned char c;
  
  if (decode) {
    for (i=0,j=0; inbuf[i] && inbuf[i] != _pad; i++) {
      if ((p = (char *)strchr(radixN, inbuf[i])) == NULL) return(1);
      D = p - radixN;
      switch (i&3) {
      case 0:
	outbuf[j] = D<<2;
	break;
      case 1:
	outbuf[j++] |= D>>4;
	outbuf[j] = (D&15)<<4;
	break;
      case 2:
	outbuf[j++] |= D>>2;
	outbuf[j] = (D&3)<<6;
	break;
      case 3:
	outbuf[j++] |= D;
      }
    }
    switch (i&3) {
    case 1: return(3);
    case 2: if (D&15) return(3);
      if (strcmp((char *)&inbuf[i], "==")) return(2);
      break;
    case 3: if (D&3) return(3);
      if (strcmp((char *)&inbuf[i], "="))  return(2);
    }
    *len = j;
  } else {
    for (i=0,j=0; i < *len; i++)
      switch (i%3) {
      case 0:
	outbuf[j++] = radixN[inbuf[i]>>2];
	c = (inbuf[i]&3)<<4;
	break;
      case 1:
	outbuf[j++] = radixN[c|inbuf[i]>>4];
	c = (inbuf[i]&15)<<2;
	break;
      case 2:
	outbuf[j++] = radixN[c|inbuf[i]>>6];
	outbuf[j++] = radixN[inbuf[i]&63];
	c = 0;
      }
    if (i%3) outbuf[j++] = radixN[c];
    switch (i%3) {
    case 1: outbuf[j++] = _pad;
    case 2: outbuf[j++] = _pad;
    }
    outbuf[*len = j] = '\0';
  }
  return(0);
}

MODULE = Krb4		PACKAGE = Krb4	PREFIX = krb4_

void
krb4_get_phost(alias)
	char *	alias

	PREINIT:
	char host[MAXHOSTNAMELEN];
	char *phost;

	PPCODE:
	phost=krb_get_phost(alias);
	strncpy(host,phost,MAXHOSTNAMELEN);
	if (host)
	{	XPUSHs(sv_2mortal(newSVpv(host,strlen(host))));
	}
	else
	{	XPUSHs(sv_2mortal(newSVsv(&sv_undef)));
	}

void
krb4_get_lrealm(n=0)
	int 	n

	PREINIT:
	char realm[REALM_SZ];
	int error;

	PPCODE:
	error=krb_get_lrealm(realm,n);
	seterror(error);
	XPUSHs(sv_2mortal(newSVpv(realm,strlen(realm))));

void
krb4_realmofhost(host)
	char *	host

	PREINIT:
	char *realm;

	PPCODE:
	realm=krb_realmofhost(host);
	seterror(0);
	XPUSHs(sv_2mortal(newSVpv(realm,strlen(realm))));

void
krb4_get_err_txt(n)
	int	n

	PPCODE:
	if (n < 0 || n > 255)
	{	XPUSHs(newSVsv(&sv_undef));
	}
	else
	{	XPUSHs(newSVpv(krb_err_txt[n],strlen(krb_err_txt[n])));
	}	

void
krb4_tkt_to_radix(auth_dat)
	SV *	auth_dat

	PREINIT:
	char *p, *s;
	long len;
	char temp[2048], buf[2048];
	KTEXT_ST ktxt;
	KTEXT auth = &ktxt;

	PPCODE:
	p = temp;

	*p++ = 1; /* version */
  
	auth->length=SvCUR(auth_dat);
	memcpy(auth->dat,SvPV(auth_dat,na),auth->length);

	PUTLONG(auth->length, p);
  
	memcpy(p, auth->dat, auth->length);
	p += auth->length;

	len = p-temp;
  
	radix_encode(temp, buf, &len, 0);
  
	XPUSHs(sv_2mortal(newSVpv(buf,len)));

void
krb4_radix_to_tkt(buf)
	char *	buf

	PREINIT:
	char *p, *s;
	int buflen, len, version, tl;
	char temp[2048];
	KTEXT_ST ktxt;
	KTEXT auth = &ktxt;

	PPCODE:
	buflen = strlen(buf);
  
	/* Make sure expansion won't overflow. */
	if (buflen*5 > sizeof(temp)*8) {
	return;
	}
  
	len = buflen;
	radix_encode(buf, temp, &len, 1);

	p = temp;
	if (len < 1) return;
	version = *p; p++; len--;

	GETLONG(auth->length, p);
	len -= 4;

	tl = auth->length;
	if (tl < 0 || tl > len || tl > sizeof(auth->dat)) return;

	memcpy(&auth->dat, p, tl);
	p += tl;
	len -= tl;

	XPUSHs(sv_2mortal(newSVpv((char *)auth->dat,auth->length)));

Krb4::Ticket
krb4_mk_req(service,instance,realm,checksum)
	char *	service
	char *	instance
	char *	realm
	unsigned long	checksum

	PREINIT:
	KTEXT authent;
	int error;

	PPCODE:
	authent=(KTEXT)safemalloc(sizeof(KTEXT_ST));
	if (!authent)
	{	XSRETURN_UNDEF;
	}
	error=krb_mk_req(authent,service,instance,realm,checksum);	
	seterror(error);
	if (error == KSUCCESS)
	{	ST(0) = sv_newmortal();
		sv_setref_pv(ST(0), "Krb4::Ticket", (void*)authent);
		XSRETURN(1);
	}
	else
	{	safefree(authent);
		XSRETURN_UNDEF;
	}

Krb4::AuthDat
krb4_rd_req(t,service,instance,fn)
	Krb4::Ticket	t
	char *	service
	char *	instance
	char *	fn

	PREINIT:
	AUTH_DAT *ad;
	int error;

	PPCODE:
	ad=(AUTH_DAT *)safemalloc(sizeof(AUTH_DAT));
	if (!ad)
	{	XSRETURN_UNDEF;
	}
	error=krb_rd_req(t,service,instance,(u_long)0,ad,fn);
	seterror(error);
	if (error == RD_AP_OK)
	{	ST(0) = sv_newmortal();
		sv_setref_pv(ST(0), "Krb4::AuthDat", (void*)ad);
		XSRETURN(1);
	}
	else
	{	safefree(ad);
		XSRETURN_UNDEF;
	}

Krb4::Creds
krb4_get_cred(service,instance,realm)
	char *	service
	char *	instance
	char *	realm

	PREINIT:
	CREDENTIALS *c;
	int error;

	PPCODE:
	c=(CREDENTIALS *)safemalloc(sizeof(CREDENTIALS));
	if (!c)
	{	XSRETURN_UNDEF;
	}
	error=krb_get_cred(service,instance,realm,c);
	seterror(error);
	if (error == GC_OK)
	{	ST(0) = sv_newmortal();
		sv_setref_pv(ST(0), "Krb4::Creds", (void*)c);
		XSRETURN(1);
	}
	else
	{	safefree(c);
		XSRETURN_UNDEF;
	}

Krb4::KeySchedule
krb4_get_key_sched(sv_session)
	SV *	sv_session

	PREINIT:
	C_Block session;
	des_key_schedule *sched;
	int error;

	PPCODE:
	sched=(des_key_schedule *)safemalloc(sizeof(des_key_schedule));
	if (!sched)
	{	XSRETURN_UNDEF;
	}
	memcpy((char *)&session,SvPV(sv_session,na),SvCUR(sv_session));
	error=des_key_sched(session,sched);
	seterror(error);
	if (error == KSUCCESS)
	{	ST(0) = sv_newmortal();
		sv_setref_pv(ST(0), "Krb4::KeySchedule", (void*)sched);
		XSRETURN(1);
	}
	else
	{	safefree(sched);
	}

void
krb4_mk_priv(s_in,schedule,key,sender,receiver)
	SV *			s_in
	Krb4::KeySchedule	schedule
	SV *			key
	SV *			sender
	SV *			receiver

	PREINIT:
	u_char *in;
	u_char *out;
	des_cblock k;
	struct sockaddr_in sender1;
	struct sockaddr_in receiver1;
	long in_length;
	long out_length;

	PPCODE:
	in_length=SvCUR(s_in);
	in=(u_char *)safemalloc(in_length);
	if (!in)
	{	seterror(-1);
		return;
	}
	out=(u_char *)safemalloc(in_length+ENC_HEADER_SZ);
	if (!out)
	{	safefree(in);
		seterror(-1);
		return;
	}
	memcpy(in,SvPV(s_in,na),SvCUR(s_in));
	memcpy(&k,SvPV(key,na),SvCUR(key));
	memcpy(&sender1,SvPV(sender,na),SvCUR(sender));
	memcpy(&receiver1,SvPV(receiver,na),SvCUR(receiver));
	out_length=krb_mk_priv(in,out,in_length,schedule,k,&sender1,&receiver1);
	safefree(in);
	XPUSHs(sv_2mortal(newSVpv(out,out_length)));

void
krb4_rd_priv(s_in,schedule,key,sender,receiver)
	SV *			s_in
	Krb4::KeySchedule	schedule
	SV *			key
	SV *			sender
	SV *			receiver

	PREINIT:
	u_char *in;
	des_cblock k;
	struct sockaddr_in sender1;
	struct sockaddr_in receiver1;
	int error;
	long in_length;
	MSG_DAT msg_data;

	PPCODE:
	in_length=SvCUR(s_in);
	in=(u_char *)safemalloc(in_length);
	if (!in)
	{	seterror(-1);
		return;
	}
	memcpy(in,SvPV(s_in,na),SvCUR(s_in));
	memcpy(&k,SvPV(key,na),SvCUR(key));
	memcpy(&sender1,SvPV(sender,na),SvCUR(sender));
	memcpy(&receiver1,SvPV(receiver,na),SvCUR(receiver));
	error=krb_rd_priv(in,in_length,schedule,k,&sender1,&receiver1,&msg_data);
	seterror(error);
	safefree(in);
	if (error == 0)
	{	XPUSHs(sv_2mortal(newSVpv(msg_data.app_data,msg_data.app_length)));
	}

MODULE = Krb4		PACKAGE = Krb4::Ticket

Krb4::Ticket
new(class,dat)
	char *	class
	SV *	dat

	PREINIT:
	KTEXT authent;
	int error;

	PPCODE:
	if (!SvOK(dat))
	{	XSRETURN_UNDEF;
	}
	authent=(KTEXT)safemalloc(sizeof(KTEXT_ST));
	if (!authent)
	{	XSRETURN_UNDEF;
	}
	authent->length=SvCUR(dat);
	memcpy(&authent->dat,SvPV(dat,na),authent->length);
	ST(0) = sv_newmortal();
	sv_setref_pv(ST(0), "Krb4::Ticket", (void*)authent);
	XSRETURN(1);

int
length(t)
	Krb4::Ticket	t

	CODE:
	RETVAL=t->length;

	OUTPUT:
	RETVAL

void
dat(t)
	Krb4::Ticket	t

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv((char *)&(t->dat),t->length)));

MODULE = Krb4		PACKAGE = Krb4::AuthDat

void
pname(ad)
	Krb4::AuthDat	ad

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv(ad->pname,strlen(ad->pname))));

void
pinst(ad)
	Krb4::AuthDat	ad

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv(ad->pinst,strlen(ad->pinst))));

void
prealm(ad)
	Krb4::AuthDat	ad

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv(ad->prealm,strlen(ad->prealm))));

void
session(ad)
	Krb4::AuthDat	ad

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv((char *)&(ad->session),sizeof(ad->session))));

void
k_flags(ad)
	Krb4::AuthDat	ad

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv((char *)&(ad->k_flags),sizeof(ad->k_flags))));

void
checksum(ad)
	Krb4::AuthDat	ad

	PPCODE:
	XPUSHs(sv_2mortal(newSVnv(ad->checksum)));

void
life(ad)
	Krb4::AuthDat	ad

	PPCODE:
	XPUSHs(sv_2mortal(newSViv(ad->life)));

void
time_sec(ad)
	Krb4::AuthDat	ad

	PPCODE:
	XPUSHs(sv_2mortal(newSVnv(ad->time_sec)));

void
address(ad)
	Krb4::AuthDat	ad

	PPCODE:
	XPUSHs(sv_2mortal(newSVnv(ad->address)));

Krb4::Ticket
reply(ad)
	Krb4::AuthDat	ad

	PPCODE:
	ST(0) = sv_newmortal();
	sv_setref_pv(ST(0), "Krb4::Ticket", (void*)&ad->reply);
	XSRETURN(1);

MODULE = Krb4		PACKAGE = Krb4::Creds

void
service(c)
	Krb4::Creds	c

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv(c->service,strlen(c->service))));

void
instance(c)
	Krb4::Creds	c

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv(c->instance,strlen(c->instance))));

void
realm(c)
	Krb4::Creds	c

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv(c->realm,strlen(c->realm))));

void
lifetime(c)
	Krb4::Creds	c

	PPCODE:
	XPUSHs(sv_2mortal(newSViv(c->lifetime)));

void
kvno(c)
	Krb4::Creds	c

	PPCODE:
	XPUSHs(sv_2mortal(newSViv(c->kvno)));

void
issue_date(c)
	Krb4::Creds	c

	PPCODE:
	XPUSHs(sv_2mortal(newSVnv(c->issue_date)));

void
session(c)
	Krb4::Creds	c

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv((char *)&(c->session),sizeof(c->session))));

Krb4::Ticket
ticket(c)
	Krb4::Creds	c

	PPCODE:
	ST(0) = sv_newmortal();
	sv_setref_pv(ST(0), "Krb4::Ticket", (void*)&c->ticket_st);
	XSRETURN(1);

void
pname(c)
	Krb4::Creds	c

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv(c->pname,strlen(c->pname))));

void
pinst(c)
	Krb4::Creds	c

	PPCODE:
	XPUSHs(sv_2mortal(newSVpv(c->pinst,strlen(c->pinst))));

