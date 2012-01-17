#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_md5.h"
#include "apr_strings.h"

module AP_MODULE_DECLARE_DATA thumb_module;

typedef struct {
    char *thumb_root;
    int   thumb_dir_depth;
    char *no_image_original;
    char *no_image_large;
    char *no_image_medium;
    char *no_image_small;
} server_config;

static apr_status_t parse_request_uri(request_rec *r, char **uri, char **size)
{
    int            nmatch = 10;
    ap_regmatch_t  match[nmatch];
    ap_regex_t    *reg;

    reg = ap_pregcomp(r->pool, "^/(original|large|medium|small)/(.*)$",
                      AP_REG_EXTENDED);
    if (ap_regexec(reg, r->unparsed_uri, nmatch, match, 0) == 0) {
        *size = ap_pregsub(r->pool, "$1", r->unparsed_uri, nmatch, match);
        *uri  = ap_pregsub(r->pool, "$2", r->unparsed_uri, nmatch, match);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Parse URI: %s, %s", *size, *uri);
        ap_pregfree(r->pool, reg);

        return APR_SUCCESS;
    }
    else {
        return APR_EGENERAL;
    }
}

static char *md5digest(request_rec *r, const char *str)
{
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char *hash = apr_palloc(r->pool, APR_MD5_DIGESTSIZE * 2 + 1);
    int  i, o;
    char hex;

    if (apr_md5(digest, str, strlen(str)) != APR_SUCCESS) {
        return NULL;
    }

    for (i = 0, o = 0; i < APR_MD5_DIGESTSIZE; ++i, o += 2) {
        hex         = (digest[i] & 0xf0) >> 4;
        hash[o]     = hex > 9 ? hex - 10 + 'a' : hex + '0';
        hex         = (digest[i] & 0xf);
        hash[o + 1] = hex > 9 ? hex - 10 + 'a' : hex + '0';
    }
    hash[APR_MD5_DIGESTSIZE * 2] = '\0';

    return hash;
}

static char *uri2thumbpath(request_rec *r, const char *uri, const char *size)
{
    server_config *conf
        = ap_get_module_config(r->server->module_config, &thumb_module);
    char *path   = "";
    char *digest = md5digest(r, uri);
    int   i;
    for (i = 0; i < conf->thumb_dir_depth; i++) {
        char sub[2] = "";
        strncpy(sub, digest + i, 1);
        path = apr_pstrcat(r->pool, path,
                           apr_pstrcat(r->pool, "/", sub, NULL), NULL);
    }
    path = apr_pstrcat(r->pool, conf->thumb_root, "/",
                       size, path, "/", digest, ".jpg", NULL);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Thumbnail path: %s", path);

    return path;
}

static char *no_image_path(request_rec *r, const char *size)
{
    server_config *conf
        = ap_get_module_config(r->server->module_config, &thumb_module);

    if (!strcmp(size, "original")) {
        return conf->no_image_original;
    }
    else if (!strcmp(size, "large")) {
        return conf->no_image_large;
    }
    else if (!strcmp(size, "medium")) {
        return conf->no_image_medium;
    }
    else if (!strcmp(size, "small")) {
        return conf->no_image_small;
    }
    else {
        return conf->no_image_medium;
    }
}

static int translate_thumb(request_rec *r)
{
    int res = ap_core_translate(r);
    if (res != OK || !r->filename) {
        return res;
    }

    char        *thumb_uri;
    char        *size;
    apr_finfo_t  finfo;
    if (parse_request_uri(r, &thumb_uri, &size) != APR_SUCCESS) {
        return DECLINED;
    }

    char *path = uri2thumbpath(r, thumb_uri, size);
    if (apr_stat(&finfo, path, APR_FINFO_INODE, r->pool) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Thumbnail does not exist: %s", path);
        path        = no_image_path(r, size);
        r->filename = path;
        r->status   = HTTP_NOT_FOUND;
    }
    else {
        r->filename = path;
    }

    return OK;
}

static void *create_server_config(apr_pool_t *p, server_rec *s)
{
    server_config *conf = apr_pcalloc(p, sizeof(server_config));

    return conf;
}

static const char
*set_thumb_root(cmd_parms *cmd, void *c, const char *arg)
{
    server_config *conf
        = ap_get_module_config(cmd->server->module_config, &thumb_module);
    conf->thumb_root = apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const char
*set_thumb_dir_depth(cmd_parms *cmd, void *c, const char *arg)
{
    server_config *conf
        = ap_get_module_config(cmd->server->module_config, &thumb_module);
    conf->thumb_dir_depth = atoi(arg);

    return NULL;
}

static const char
*set_no_image_medium(cmd_parms *cmd, void *c, const char *arg)
{
    server_config *conf
        = ap_get_module_config(cmd->server->module_config, &thumb_module);
    conf->no_image_medium = apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const char
*set_no_image_small(cmd_parms *cmd, void *c, const char *arg)
{
    server_config *conf
        = ap_get_module_config(cmd->server->module_config, &thumb_module);
    conf->no_image_small = apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const command_rec command_table[] = {
    AP_INIT_TAKE1("ThumbRoot", set_thumb_root,
                  NULL, RSRC_CONF, "The path to humbnail root directory"),
    AP_INIT_TAKE1("ThumbDirDepth", set_thumb_dir_depth,
                  NULL, RSRC_CONF, "The number of subdirectories in the ThumbRootDir"),
    AP_INIT_TAKE1("ThumbNoImageMedium", set_no_image_medium,
                  NULL, RSRC_CONF, "The path to medium size no image"),
    AP_INIT_TAKE1("ThumbNoImageSmall", set_no_image_small,
                  NULL, RSRC_CONF, "The path to small size no image"),
    {NULL},
};

static void thumb_register_hooks(apr_pool_t *p)
{
    ap_hook_translate_name(translate_thumb, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA thumb_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    create_server_config,  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    command_table,         /* table of config file commands       */
    thumb_register_hooks   /* register hooks                      */
};
