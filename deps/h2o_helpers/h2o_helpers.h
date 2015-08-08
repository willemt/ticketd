#ifndef H2O_HELPERS_H
#define H2O_HELPERS_H

int h2oh_respond_with_error(h2o_req_t *req, const int status_code, const char* reason);

int h2oh_respond_with_success(h2o_req_t *req, const int status_code);

#endif /* H2O_HELPERS_H */
