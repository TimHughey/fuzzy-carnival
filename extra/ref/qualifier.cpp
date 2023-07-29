void handle_get_info(__attribute((unused)) rtsp_conn_info *conn, rtsp_message *req,
                     rtsp_message *resp)
{
  debug_log_rtsp_message(2, "GET /info:", req);
  if (rtsp_message_contains_plist(req))
  { // it's stage one
    // get version of AirPlay -- it might be too old. Not using it yet.
    char *hdr = msg_get_header(req, "User-Agent");
    if (hdr)
    {
      if (strstr(hdr, "AirPlay/") == hdr)
      {
        hdr = hdr + strlen("AirPlay/");
        // double airplay_version = 0.0;
        // airplay_version = atof(hdr);
        debug(2, "Connection %d: GET_INFO: Source AirPlay Version is: %s.", conn->connection_number,
              hdr);
      }
    }
    plist_t info_plist = NULL;
    plist_from_memory(req->content, req->contentlength, &info_plist);

    plist_t qualifier = plist_dict_get_item(info_plist, "qualifier");
    if (qualifier == NULL)
    {
      debug(1, "GET /info Stage 1: plist->qualifier was NULL");
      goto user_fail;
    }
    if (plist_array_get_size(qualifier) < 1)
    {
      debug(1, "GET /info Stage 1: plist->qualifier array length < 1");
      goto user_fail;
    }
    plist_t qualifier_array_value = plist_array_get_item(qualifier, 0);
    char *qualifier_array_val_cstr;
    plist_get_string_val(qualifier_array_value, &qualifier_array_val_cstr);
    if (qualifier_array_val_cstr == NULL)
    {
      debug(1, "GET /info Stage 1: first item in qualifier array not a string");
      goto user_fail;
    }
    debug(2, "GET /info Stage 1: qualifier: %s", qualifier_array_val_cstr);
    plist_free(info_plist);
    free(qualifier_array_val_cstr);

    // uint8_t bt_addr[6] = {0xB8, 0x27, 0xEB, 0xB7, 0xD4, 0x0E};
    plist_t response_plist = NULL;
    plist_from_xml((const char *)plists_get_info_response_xml, plists_get_info_response_xml_len,
                   &response_plist);
    if (response_plist == NULL)
    {
      debug(1, "GET /info Stage 1: response plist not created from XML!");
    }
    else
    {
      void *qualifier_response_data = NULL;
      size_t qualifier_response_data_length = 0;
      if (add_pstring_to_malloc("acl=0", &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc(deviceIdString, &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc(featuresString, &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc("rsf=0x0", &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc("flags=0x4", &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc("model=Shairport Sync", &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc("manufacturer=", &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc("serialNumber=", &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc("protovers=1.1", &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc("srcvers=366.0", &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc(piString, &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc(gidString, &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      if (add_pstring_to_malloc("gcgl=0", &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      snprintf(pkString, sizeof(pkString), "pk=");
      pkString_make(pkString + strlen("pk="), sizeof(pkString) - strlen("pk="),
                    config.airplay_device_id);
      if (add_pstring_to_malloc(pkString, &qualifier_response_data,
                                &qualifier_response_data_length) == 0)
        debug(1, "Problem");
      // debug(1,"qualifier_response_data_length: %u.", qualifier_response_data_length);

      plist_dict_set_item(response_plist, "txtAirPlay",
                          plist_new_data(qualifier_response_data, qualifier_response_data_length));

      plist_dict_set_item(response_plist, "features", plist_new_uint(config.airplay_features));
      plist_dict_set_item(response_plist, "statusFlags",
                          plist_new_uint(config.airplay_statusflags));
      plist_dict_set_item(response_plist, "deviceID", plist_new_string(config.airplay_device_id));
      plist_dict_set_item(response_plist, "pi", plist_new_string(config.airplay_pi));
      plist_dict_set_item(response_plist, "name", plist_new_string(config.service_name));
      char *vs = get_version_string();
      //      plist_dict_set_item(response_plist, "model", plist_new_string(vs));
      plist_dict_set_item(response_plist, "model", plist_new_string("Shairport Sync"));
      free(vs);
      // pkString_make(pkString, sizeof(pkString), config.airplay_device_id);
      // plist_dict_set_item(response_plist, "pk", plist_new_string(pkString));
      plist_to_bin(response_plist, &resp->content, &resp->contentlength);
      if (resp->contentlength == 0)
        debug(1, "GET /info Stage 1: response bplist not created!");
      plist_free(response_plist);
      free(qualifier_response_data);
    }
    msg_add_header(resp, "Content-Type", "application/x-apple-binary-plist");
    debug_log_rtsp_message(2, "GET /info Stage 1 Response:", resp);
    resp->respcode = 200;
    return;

  user_fail:
    resp->respcode = 400;
    return;
  }
  else
  { // stage two
    plist_t response_plist = NULL;
    plist_from_xml((const char *)plists_get_info_response_xml, plists_get_info_response_xml_len,
                   &response_plist);
    plist_dict_set_item(response_plist, "features", plist_new_uint(config.airplay_features));
    plist_dict_set_item(response_plist, "statusFlags", plist_new_uint(config.airplay_statusflags));
    plist_dict_set_item(response_plist, "deviceID", plist_new_string(config.airplay_device_id));
    plist_dict_set_item(response_plist, "pi", plist_new_string(config.airplay_pi));
    plist_dict_set_item(response_plist, "name", plist_new_string(config.service_name));
    char *vs = get_version_string();
    // plist_dict_set_item(response_plist, "model", plist_new_string(vs));
    plist_dict_set_item(response_plist, "model", plist_new_string("Shairport Sync"));
    free(vs);
    // pkString_make(pkString, sizeof(pkString), config.airplay_device_id);
    // plist_dict_set_item(response_plist, "pk", plist_new_string(pkString));
    plist_to_bin(response_plist, &resp->content, &resp->contentlength);
    plist_free(response_plist);
    msg_add_header(resp, "Content-Type", "application/x-apple-binary-plist");
    debug_log_rtsp_message(2, "GET /info Stage 2 Response", resp);
    resp->respcode = 200;
    return;
  }
}
