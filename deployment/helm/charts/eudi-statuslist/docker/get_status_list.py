
@token.route("/<country>/<doctype>/<list>", methods=["GET"])
def get_status_list(country, doctype, list):
    accept = (request.headers.get("Accept") or "").lower()

    def accepts(*media_types: str) -> bool:
        if not accept or accept.strip() in {"*", "*/*"}:
            return "application/statuslist+jwt" in media_types
        for part in accept.split(","):
            mt = part.split(";", 1)[0].strip()
            if mt in media_types or mt in {"*", "*/*"}:
                return True
        return False

    if accepts("application/statuslist+jwt"):
        filename = "token_status_list.jwt"
        mimetype = "application/statuslist+jwt"
    elif accepts("application/statuslist+cwt"):
        filename = "token_status_list.cwt"
        mimetype = "application/statuslist+cwt"
    else:
        return jsonify({"error": "Not Acceptable", "accept": request.headers.get("Accept")}), 406

    import os
    file_path = os.path.join(cfgservice.status_list_dir, "token_status_list", country, doctype, list, filename)

    if not os.path.isfile(file_path):
        return "", 404

    from flask import send_file
    return send_file(file_path, mimetype=mimetype)
