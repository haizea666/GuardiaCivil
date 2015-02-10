        AuditLogger.getInstance().logAccess(getClass(), "onLoginSuccess()","Acceso de "+userUid+" desde MAC: "+clientMacAddr, ssoToken);
        
        try{
            String dnname = ssoToken.getPrincipal().getName();
            String username = getBasicPrincipalName(dnname);
            boolean is_ok = false;
            if (MODE.equalsIgnoreCase("file")) {
                is_ok = setUserDataFromFile(username, ssoToken);
            } else {
                is_ok = setUserDataFromDB(username, ssoToken);
            }
            System.out.println("Loaded data from file to session:" + is_ok);
            if (is_ok) {
                Logger.getLogger(GCPostAuthModule_backup.class.getName()).log(Level.SEVERE, null, "OK");
                AuditLogger.getInstance().debugLogMessage(getClass(), "onLoginSuccess()", "OK");
            } else {
                Logger.getLogger(GCPostAuthModule_backup.class.getName()).log(Level.SEVERE, null, "ERROR LOADING USER DATA");
                AuditLogger.getInstance().debugLogError(getClass(), "onLoginSuccess()", "ERROR LOADING USER DATA");
                throw new SSOException("ERROR LOADING USER DATA");
            }
        } catch (SSOException ex) {
            AuditLogger.getInstance().debugLogError(getClass(), "onLoginSuccess()", "Entrando en la excepcion 1" + ex.getMessage());
            Logger.getLogger(GCPostAuthModule_backup.class.getName()).log(Level.SEVERE, null, ex);

            throw new AuthenticationException("ERROR de Autenticacion");
        } catch (NamingException ex) {
            AuditLogger.getInstance().debugLogError(getClass(), "onLoginSuccess()", "Entrando en la excepcion 2" + ex.getMessage());
            Logger.getLogger(GCPostAuthModule_backup.class.getName()).log(Level.SEVERE, null, ex);

            throw new AuthenticationException("ERROR de Autenticacion");
        } catch (Exception e) {
            AuditLogger.getInstance().debugLogError(getClass(), "onLoginSuccess()", "Entrando en la excepcion 3" + e.getMessage());
        }
        
    }

    /**
     * Post processing on failed authentication.
     *
     * @param requestParamsMap contains HttpServletRequest parameters
     * @param req HttpServlet request
     * @param res HttpServlet response
     * @throws AuthenticationException if there is an error
     */
    public void onLoginFailure(Map requestParamsMap,
            HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {
        if(AuditLogger.DEBUG){
            AuditLogger.getInstance().debugLogMessage(getClass(), "onLoginFailure()", "Starting...");
//            showRequestParameters(request);
        }
        
        String clientMacAddr = null;
        try{
            clientMacAddr = getClientMacAddress(request, null);
        }catch(SSOException e){
            AuditLogger.getInstance().debugLogError(getClass(), "onLoginFailure()", "Error getting client mac address: "+e+"->"+e.getMessage());
        }
        if (clientMacAddr == null) clientMacAddr = "UNKNOWN_MAC";
        AuditLogger.getInstance().logError(getClass(), "onLoginFailure()","Acceso incorrecto de "+request.getParameter(LOGIN_PARAM_NAME)+" desde MAC: "+clientMacAddr);
        
    }

    /**
     * Post processing on Logout.
     *
     * @param req HttpServlet request
     * @param res HttpServlet response
     * @param ssoToken user's session
     * @throws AuthenticationException if there is an error
     */
    public void onLogout(HttpServletRequest request,
            HttpServletResponse response,
            SSOToken ssoToken) throws AuthenticationException {
        if(AuditLogger.DEBUG){
            AuditLogger.getInstance().debugLogMessage(getClass(), "onLogout()", "Starting...");
//            showRequestParameters(request);
        }
        
        String clientMacAddr = null;
        try{
            clientMacAddr = getClientMacAddress(request, ssoToken);
        }catch(SSOException e){
            AuditLogger.getInstance().debugLogError(getClass(), "onLoginSuccess()", "Error getting client mac address: "+e+"->"+e.getMessage());
        }
        if (clientMacAddr == null) clientMacAddr = "UNKNOWN_MAC";
        String userUid = "UNKNOWN_USER";
        try{
            Principal user = ssoToken.getPrincipal();
            if (user != null) userUid = user.getName();
        }catch(SSOException e){
            AuditLogger.getInstance().debugLogError(getClass(), "onLoginSuccess()", "Cannot retrieve principal from sso token.");
        }
        AuditLogger.getInstance().logAccess(getClass(), "onLogout()","Fin de sesion de "+userUid+" desde MAC: "+clientMacAddr, ssoToken);

    }

    private String getClientMacAddress(HttpServletRequest request, SSOToken ssoToken) throws SSOException{
        String clientMacAddr = request.getParameter(MAC_ADDR_PARAM_NAME);
        if (clientMacAddr == null){
            if(ssoToken != null)
                clientMacAddr = ssoToken.getProperty(MAC_ADDR_PARAM_NAME);
        } else {
            if(ssoToken != null)
                ssoToken.setProperty(MAC_ADDR_PARAM_NAME, clientMacAddr);
        }
        
        return clientMacAddr;
    }
    
    private void showRequestParameters(HttpServletRequest request){
        Enumeration<String> paramNames = request.getParameterNames();
        while (paramNames.hasMoreElements()){
            String paramName = paramNames.nextElement();
            String paramValue = request.getParameter(paramName);
            AuditLogger.getInstance().debugLogMessage(getClass(), "showRequestParameters()", paramName+": "+paramValue);
        }
    }
    
    
    
    
    
    /* User Object Management */
    

    //-------------------------------------------------------------------------
    /**
     * Returns a remote reference to the Session Manager.
     *
     * @return Reference to Session Manager.
     * @throws SSOSystemException If any error ocurrs while trying to get the
     * reference.
     */
    //-------------------------------------------------------------------------
    private HashMap getUserRoles(String username, ArrayList aplicaciones)
            throws SSOException {
        return null;
    }
    //-------------------------------------------------------------------------

    /**
     * Returns a remote reference to the Session Manager.
     *
     * @return Reference to Session Manager.
     * @throws SSOSystemException If any error ocurrs while trying to get the
     * reference.
     */
    //-------------------------------------------------------------------------
    private HashMap getUserData(String userid) throws SSOException {

        InitialContext ctx;
        DataSource ds;
        Connection conn = null;
        CallableStatement cs = null;
        ResultSet rs = null;
        try {
            ctx = new InitialContext();
            ds = (DataSource) ctx.lookup(resourceJNDIName);
            conn = ds.getConnection();
            String cs_query = "{call stored_procedure(?,?)}";
            cs = conn.prepareCall(cs_query);
            cs.registerOutParameter(1, Types.VARCHAR);
            cs.setString(2, userid);
            cs.execute();
            String str = cs.getString(1);
            if (str != null) {
                System.out.println(str);
            } else {
                rs = cs.getResultSet();
                while (rs.next()) {
                    System.out.println("Name : " + rs.getString(2));
                }
            }
        } catch (SQLException ex) {
            Logger.getLogger(GCPostAuthModule_backup.class.getName()).log(Level.SEVERE, null, ex);
            throw new SSOException(ex);
        } catch (NamingException ex) {
            Logger.getLogger(GCPostAuthModule_backup.class.getName()).log(Level.SEVERE, null, ex);
            throw new SSOException(ex);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                    System.err.println("SQLException: " + e.getMessage());
                }
            }
            if (cs != null) {
                try {
                    cs.close();
                } catch (SQLException e) {
                    System.err.println("SQLException: " + e.getMessage());
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    System.err.println("SQLException: " + e.getMessage());
                }
            }
        }

        return null;
    }

    private boolean setUserDataFromDB(String userid, SSOToken ssoToken) throws SSOException, NamingException {
        System.out.println("Calling setUSerDataFromDB with:" + userid + " and tokenid:" + ssoToken.getTokenID().toString());
        InitialContext ctx;
        DataSource ds;
        Connection conn = null;
        CallableStatement cs = null;
        CallableStatement cs_app = null;
        String ncodusuario = null;
        ResultSet cursorAplicaciones = null;
        ResultSet cursorIdentificadores = null;
        try {
            ctx = new InitialContext();
            ds = (DataSource) ctx.lookup(resourceJNDIName);
            conn = ds.getConnection();
            cs = conn.prepareCall(query_datos_usuario,
                    ResultSet.TYPE_SCROLL_INSENSITIVE,
                    ResultSet.CONCUR_READ_ONLY);
            System.out.print("call prepared");
            cs.registerOutParameter(1, Types.INTEGER);
            cs.setString(2, userid);
            cs.registerOutParameter(3, Types.VARCHAR); //n_cod_usuario
            cs.registerOutParameter(4, Types.VARCHAR); //ades_nombre
            cs.registerOutParameter(5, Types.VARCHAR); //ades_apellido1
            cs.registerOutParameter(6, Types.VARCHAR); //ades_apellido2
            cs.registerOutParameter(7, Types.VARCHAR); //unidad_destino
            cs.registerOutParameter(8, Types.VARCHAR); //p_ades_unidad_destino
            cs.registerOutParameter(9, Types.VARCHAR); //tipo_usuario
            cs.registerOutParameter(10, OracleTypes.CURSOR); //aplicaciones
            cs.registerOutParameter(11, OracleTypes.CURSOR); //identificadores


            cs.execute();
            int resultado = cs.getInt(1);
            if (resultado == 1) {
                ssoToken.setProperty("idTipoUsuario", cs.getString(9));
                ncodusuario = cs.getString(3);
                ssoToken.setProperty("nCodUsuario", ncodusuario);
                ssoToken.setProperty("aCodUsuario", userid);
                ssoToken.setProperty("nombreUsuario", cs.getString(4));
                ssoToken.setProperty("apellido1Usuario", cs.getString(5));
                ssoToken.setProperty("apellido2Usuario", cs.getString(6));
                ssoToken.setProperty("codUnidadDestino", cs.getString(7));
                ssoToken.setProperty("adesUnidadDestino", cs.getString(8));

                String listaaplicaciones = "";


                //Recuperamos los permisos y se meten en un HashMap
                cursorAplicaciones = (ResultSet) cs.getObject(10);  //Permisos

                if (cursorAplicaciones == null) {
                    System.out.println("El cursor de aplicaciones es vacio");
                } else {
                    System.out.println("LISTA DE APLICACIONES");
                    String cs_query_app = query_permisos_aplicacion;
                    cs_app = conn.prepareCall(cs_query_app,
                            ResultSet.TYPE_SCROLL_INSENSITIVE,
                            ResultSet.CONCUR_READ_ONLY);
                    while (cursorAplicaciones.next()) {
                        ResultSet cursorRoles = null;
                        ResultSet cursorPermisos = null;
                        ResultSet cursorDelegaciones = null;
                        String datosaplicacion = "";
                        String ncod_aplicacion = cursorAplicaciones.getString(1);
                        if (listaaplicaciones.equalsIgnoreCase("")) {
                            listaaplicaciones = ncod_aplicacion;
                        } else {
                            listaaplicaciones = listaaplicaciones + "|" + ncod_aplicacion;
                        }
                        String tipo_aplicacion = cursorAplicaciones.getString(4);
                        System.out.println("Aplicacion:" + ncod_aplicacion 
                                + "|" + cursorAplicaciones.getString(2) //nombre completo de la aplicacion
                                + "|" + cursorAplicaciones.getString(3)  //URL completa
                                + "|" + cursorAplicaciones.getString(4) //numero
                                + "|" + cursorAplicaciones.getString(5)); //numero
                        String contextoapp = getContextoFromURL(cursorAplicaciones.getString(3));
                        System.out.println("---------------------------CONTEXTO:" + contextoapp);
                        String URL= cursorAplicaciones.getString(3).trim();
                        datosaplicacion = "ncodAplicacion#" + ncod_aplicacion + "|"
                                + "adesNombre#" + cursorAplicaciones.getString(2) + "|"
                                + "adesContexto#" + contextoapp + "|"
                                + "ncodTipoAplicacion#" + tipo_aplicacion + "|"
                                + "nindEstado#" + cursorAplicaciones.getString(5) + "|"
                                + "URL#"+URL;

                        if (tipo_aplicacion.equalsIgnoreCase("2")) {
                            //La aplicacion es del tipo corporativo y no recogo roles ni permisos
                        } else {
                            try {
                                cs_app.registerOutParameter(1, Types.INTEGER);
                                cs_app.setInt(2, Integer.parseInt(ncodusuario));
                                cs_app.setInt(3, Integer.parseInt(ncod_aplicacion));
                                cs_app.registerOutParameter(4, Types.VARCHAR); //p_unidad_acceso
                                cs_app.registerOutParameter(5, Types.VARCHAR); //p_ades_unidad_acceso
                                cs_app.registerOutParameter(6, Types.VARCHAR); //p_ncod_grupo
                                cs_app.registerOutParameter(7, Types.VARCHAR); //p_ades_grupo
                                cs_app.registerOutParameter(8, OracleTypes.CURSOR); //permisos
                                cs_app.registerOutParameter(9, OracleTypes.CURSOR); //roles
                                cs_app.registerOutParameter(10, OracleTypes.CURSOR); //delegaciones

                                cs_app.execute();
                                int resultado_app = cs_app.getInt(1);
                                if (resultado_app == 1) {


                                    for (int i = 4; i <= 7; i++) {
                                        System.out.println("---------------Dato_app" + i + ":" + cs.getString(i));
                                    }

                                    datosaplicacion = datosaplicacion + "|"
                                            + "codUnidadAcceso#" + cs_app.getString(4) + "|"
                                            + "adesUnidadAcceso#" + cs_app.getString(5) + "|"
                                            + "codGrupo#" + cs_app.getString(6) + "|"
                                            + "adesGrupo#" + cs_app.getString(7);

                                    //Recuperamos los permisos y se meten en un HashMap
                                    String lista_codigos_permisos = "";
                                    String lista_detalle_permisos = "";
                                    cursorPermisos = (ResultSet) cs_app.getObject(8);  //Permisos
                                    if (cursorPermisos == null) {
                                        System.out.println("---------------El cursor de permisos es vacio");
                                    } else {
                                        System.out.println("---------------LISTA DE PERMISOS");
                                    }
                                    while (cursorPermisos.next()) {
                                        String ncod_permiso = cursorPermisos.getString(1);
                                        if (lista_codigos_permisos.equalsIgnoreCase("")) {
                                            lista_codigos_permisos = ncod_permiso;
                                            lista_detalle_permisos = cursorPermisos.getString(2);
                                        } else {
                                            lista_codigos_permisos = lista_codigos_permisos + "|" + ncod_permiso;
                                            lista_detalle_permisos = lista_detalle_permisos + "|" + cursorPermisos.getString(2);
                                        }
                                        System.out.println("-----------------------Permiso:" + ncod_permiso
                                                + "|" + cursorPermisos.getString(2));
                                        System.out.println("-----------------------lista de permisos:" + lista_codigos_permisos);
                                        System.out.println("-----------------------lista de detalles permisos:" + lista_detalle_permisos);

                                    }
                                    ssoToken.setProperty("codigo_permisos_" + contextoapp, lista_codigos_permisos);
                                    ssoToken.setProperty("detalle_permisos_" + contextoapp, lista_detalle_permisos);
                                    String lista_codigos_roles = "";
                                    String lista_detalle_roles = "";
                                    //Recuperamos los permisos y se meten en un HashMap
                                    cursorRoles = (ResultSet) cs_app.getObject(9);  //Permisos
                                    if (cursorRoles == null) {
                                        System.out.println("---------------El cursor de roles es vacio");
                                    } else {
                                        System.out.println("---------------LISTA DE ROLES");
                                    }
                                    while (cursorRoles.next()) {
                                        if (lista_codigos_roles.equalsIgnoreCase("")) {
                                            lista_codigos_roles = cursorRoles.getString(1);
                                            lista_detalle_roles = cursorRoles.getString(2);
                                        } else {
                                            lista_codigos_roles = lista_codigos_roles + "|" + cursorRoles.getString(1);
                                            lista_detalle_roles = lista_detalle_roles + "|" + cursorRoles.getString(2);
                                        }
                                        System.out.println("-----------------------Role:" + cursorRoles.getString(1) + "|" + cursorRoles.getString(2));
                                        System.out.println("-----------------------lista de roles:" + lista_codigos_roles);
                                        System.out.println("-----------------------lista de detalles roles:" + lista_detalle_roles);
                                    }

                                    ssoToken.setProperty("codigo_roles_" + contextoapp, lista_codigos_roles);
                                    ssoToken.setProperty("detalle_roles_" + contextoapp, lista_detalle_roles);

                                    String lista_delegaciones = "";
                                    //Recuperamos las delegaciones y se meten en un HashMap
                                    cursorDelegaciones = (ResultSet) cs_app.getObject(10);  //Delegaciones
                                    if (cursorDelegaciones == null) {
                                        System.out.println("---------------El cursor de delegaciones es vacio");
                                    } else {
                                        System.out.println("---------------LISTA DE DELEGACIONES");
                                        while (cursorDelegaciones.next()) {
                                            String codigo_delegacion = cursorDelegaciones.getString(1);
                                            if (!codigo_delegacion.equalsIgnoreCase("-1")) {
                                                String delegacion = codigo_delegacion + "#"
                                                        + cursorDelegaciones.getString(2) + "#" //ncodapli
                                                        + cursorDelegaciones.getString(3) + "#"
                                                        + cursorDelegaciones.getString(4) + "#"
                                                        + cursorDelegaciones.getString(5) + "#" //ncodTipo
                                                        + cursorDelegaciones.getString(6) + "#"
                                                        + cursorDelegaciones.getString(7) + "#"
                                                        + cursorDelegaciones.getString(8) + "#"
                                                        + cursorDelegaciones.getString(9);
                                                if (lista_delegaciones.equalsIgnoreCase("")) {
                                                    lista_delegaciones = delegacion;
                                                } else {
                                                    lista_delegaciones = lista_delegaciones + "|" + delegacion;

                                                }
                                            }

                                        }
                                        System.out.println("-----------------------Delegaciones:" + lista_delegaciones);
                                        if (!lista_delegaciones.equalsIgnoreCase("")) {
                                            ssoToken.setProperty("delegaciones_" + contextoapp, lista_delegaciones);
                                        }
                                    }

                                }
                            } catch (SQLException sqlEx) {
                                sqlEx.printStackTrace();
                                throw new SSOException("Error de autenticación:" + sqlEx.toString());
                            } finally {
                                try {
                                    if (cursorPermisos != null) {
                                        cursorPermisos.close();
                                    }
                                    if (cursorRoles != null) {
                                        cursorRoles.close();
                                    }
                                } catch (SQLException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                        ssoToken.setProperty("datos_" + contextoapp, datosaplicacion);
                        System.out.println(".......................datos_aplicacion:" + datosaplicacion);

                    }
                    ssoToken.setProperty("listaaplicaciones", listaaplicaciones);
                }
                //Recuperamos los permisos y se meten en un HashMap
                cursorIdentificadores = (ResultSet) cs.getObject(11);  //Permisos
                if (cursorIdentificadores == null) {
                    System.out.println("El cursor de identificadores es vacio");
                } else {
                    System.out.println("LISTA DE IDENTIFICADORES");
                    String listaIdentificadores = "";
                    while (cursorIdentificadores.next()) {
                        System.out.println("Identificador:" + cursorIdentificadores.getString(1));
                        if (listaIdentificadores.equalsIgnoreCase("")) {
                            listaIdentificadores = cursorIdentificadores.getString(1) + "~" + cursorIdentificadores.getString(2);
                        } else {
                            listaIdentificadores = listaIdentificadores + "|" + cursorIdentificadores.getString(1) + "~" + cursorIdentificadores.getString(2);
                        }

                    }
                    ssoToken.setProperty("identificadores", listaIdentificadores);
                }

            } else {
                System.out.println("El resultado es 0");
            }
        } catch (SQLException sqlEx) {
            sqlEx.printStackTrace();
            throw new SSOException("Error de autenticación:" + sqlEx.toString());
        } finally {
            try {
                if (cursorAplicaciones != null) {
                    cursorAplicaciones.close();
                }
                if (cursorIdentificadores != null) {
                    cursorIdentificadores.close();
                }
                if (cs != null) {
                    cs.close();
                }
                if (cs_app != null) {
                    cs_app.close();
                }
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
                return false;
            }
        }
        return true;
    }
    //-------------------------------------------------------------------------

    /**
     * Returns a remote reference to the Session Manager.
     *
     * @return Reference to Session Manager.
     * @throws SSOSystemException If any error ocurrs while trying to get the
     * reference.
     */
    //-------------------------------------------------------------------------
    public static String getContextoFromURL(String url) {
        int veces = 3;
        if (url.indexOf("/") == -1) {
            return url;
        } else {
            StringTokenizer st = new StringTokenizer(url, "/");
            if (st.countTokens() < 3) {
                veces = st.countTokens();
            }
            String lastString = "";
            int ntimes = 1;
            while (((lastString = st.nextToken()) != null) && (ntimes < veces)) {
                ntimes++;
            }
            return lastString;
        }
    }

    private boolean setUserDataFromFile(String username, SSOToken ssoToken) throws SSOException {
        System.out.println("Loading user file with:" + username + " and tokenid:" + ssoToken.getTokenID().toString());
        HashMap<String, String> userdata = cargarFicheroUsuarios();
        System.out.println("User file loaded setting session values");
        Set keys = userdata.keySet();
        Iterator keysit = keys.iterator();
        while (keysit.hasNext()) {
            String key = (String) keysit.next();
            ssoToken.setProperty(key, userdata.get(key));
            System.out.println("setting session:<key>:" + key + " <value>:" + userdata.get(key));
        }
        return true;
    }

    private String getBasicPrincipalName(String dnname) {
        if (dnname != null) {
            StringTokenizer st = new StringTokenizer(dnname, ",");
            String namevalue = st.nextToken();
            StringTokenizer st2 = new StringTokenizer(namevalue, "=");
            st2.nextToken();
            return st2.nextToken();
        }
        return null;
    }

    /**
     * Carga la estructura HashMap interna a partir del contenido del fichero de
     * usuarios (Usuarios.Properties)
     *
     * @throws AuditorException
     *
     */
    private HashMap<String, String> cargarFicheroUsuarios() {
        HashMap<String, String> hMapUsuarios = null;
        Properties prop = new Properties();

        System.out.println("loading file........");
        try {
            FileInputStream userdata = new FileInputStream("/home/haizea/properties/usuario.properties");
            System.out.println("resource obtained, trying to load in properties....");
            prop.load(userdata);
            System.out.println("Properties file loaded:" + prop.toString());

        } catch (IOException e) {
            System.out.println("Exception loading file:" + e);

        }

        //Insertamos todas las propiedades leidas dentro de nuestro hashMap interno
        hMapUsuarios = new HashMap<String, String>();
        System.out.println("Obtaining enumeration from properties variable");
        Enumeration<?> e = prop.keys();
        System.out.println("Enumeration created with keys:" + e.toString());

        while (e.hasMoreElements()) {
            String strKey = (String) e.nextElement();
            hMapUsuarios.put(strKey, prop.getProperty(strKey));
            System.out.println("Establishing hashMap with file values:<key>:" + strKey + "<value>:" + prop.getProperty(strKey));
        }//while
        System.out.println("returning hmapusuarios:" + hMapUsuarios);
        return hMapUsuarios;
    }//cargarFicheroUsuarios
    
}

