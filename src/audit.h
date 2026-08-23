#ifndef SKY_SECRET_AUDIT_H
#define SKY_SECRET_AUDIT_H

int audit_append(const char *path, const char *action, const char *namespace_name, const char *secret_name, const char *result);

#endif
