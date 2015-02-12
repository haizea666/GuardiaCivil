package es.corenetworks.sso.postauth;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.spi.AMPostAuthProcessInterface;
import com.sun.identity.authentication.spi.AuthenticationException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.Principal;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import oracle.jdbc.OracleTypes;

public class GCPostAuthModule
  implements AMPostAuthProcessInterface
{
  private static final String MODE = "db";
  private static final String query_datos_usuario = "{? = call pkg_pc_core.fnc_get_datos_usu(?,?,?,?,?,?,?,?,?,?)}";
  private static final String query_permisos_aplicacion = "{? = call pkg_pc_core.fnc_get_datos_usu_apli(?,?,?,?,?,?,?,?,?)}";
  private static String resourceJNDIName = "jdbc/sso";
  private Logger logger = Logger.getLogger(GCPostAuthModule.class.getName());

  public void onLoginSuccess(Map requestParamsMap, HttpServletRequest request, HttpServletResponse response, SSOToken ssoToken) throws AuthenticationException {
    this.logger.log(Level.INFO, null, "postAuth.onLoginSuccess called: Req:" + request.getRequestURL());

    System.out.println("postAuth.onLoginSuccess called: Req:" + request.getRequestURL());
    try
    {
      String dnname = ssoToken.getPrincipal().getName();
      String username = getBasicPrincipalName(dnname);
      System.out.println("Obtaining name:" + username);
      boolean is_ok = false;
      if ("db".equalsIgnoreCase("file")) {
        is_ok = setUserDataFromFile(username, ssoToken);
        System.out.println("Loaded data from file to session:" + is_ok);
      } else {
        is_ok = setUserDataFromDB(username, ssoToken);
      }

      if (is_ok) {
        this.logger.log(Level.SEVERE, null, "OK");
      } else {
        this.logger.log(Level.SEVERE, null, "ERROR LOADING USER DATA");
        throw new SSOException("ERROR LOADING USER DATA");
      }
    } catch (SSOException ex) {
      this.logger.log(Level.SEVERE, null, ex);
      throw new AuthenticationException("ERROR de Autenticacion");
    } catch (NamingException ex) {
      this.logger.log(Level.SEVERE, null, ex);
      throw new AuthenticationException("ERROR de Autenticacion");
    }
  }

  public void onLoginFailure(Map requestParamsMap, HttpServletRequest req, HttpServletResponse res)
    throws AuthenticationException
  {
    this.logger.log(Level.INFO, null, "postAuth.onLoginFailure: called");
  }

  public void onLogout(HttpServletRequest request, HttpServletResponse response, SSOToken ssoToken)
    throws AuthenticationException
  {
    this.logger.log(Level.INFO, null, "postAuth.onLogout called");
  }

  private HashMap getUserRoles(String username, ArrayList aplicaciones)
    throws SSOException
  {
    return null;
  }

  private HashMap getUserData(String userid)
    throws SSOException
  {
    Connection conn = null;
    CallableStatement cs = null;
    ResultSet rs = null;
    try {
      InitialContext ctx = new InitialContext();
      DataSource ds = (DataSource)ctx.lookup(resourceJNDIName);
      conn = ds.getConnection();
      String cs_query = "{call stored_procedure(?,?)}";
      cs = conn.prepareCall(cs_query);
      cs.registerOutParameter(1, 12);
      cs.setString(2, userid);
      cs.execute();
      String str = cs.getString(1);
      if (str != null) {
        System.out.println(str);
      } else {
        rs = cs.getResultSet();
        while (rs.next())
          System.out.println("Name : " + rs.getString(2));
      }
    }
    catch (SQLException ex) {
      this.logger.log(Level.SEVERE, null, ex);
      throw new SSOException(ex);
    } catch (NamingException ex) {
      this.logger.log(Level.SEVERE, null, ex);
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

  private boolean setUserDataFromDB(String userid, SSOToken ssoToken)
    throws SSOException, NamingException
  {
    System.out.println("Calling setUSerDataFromDB with:" + userid + " and tokenid:" + ssoToken.getTokenID().toString());

    Connection conn = null;
    CallableStatement cs = null;
    CallableStatement cs_app = null;
    String ncodusuario = null;
    ResultSet cursorAplicaciones = null;
    ResultSet cursorIdentificadores = null;
    try {
      InitialContext ctx = new InitialContext();
      DataSource ds = (DataSource)ctx.lookup(resourceJNDIName);
      conn = ds.getConnection();
      cs = conn.prepareCall("{? = call pkg_pc_core.fnc_get_datos_usu(?,?,?,?,?,?,?,?,?,?)}", 1004, 1007);

      System.out.print("call prepared");
      cs.registerOutParameter(1, Types.INTEGER);
      cs.setString(2, userid);
      cs.registerOutParameter(3, Types.VARCHAR); //n_cod_usuario
      cs.registerOutParameter(4, Types.VARCHAR); //ades_nombre
      cs.registerOutParameter(5, Types.VARCHAR); //ades_apellido1
      cs.registerOutParameter(6, Types.VARCHAR); //ades_apellido2
      cs.registerOutParameter(7, Types.VARCHAR); //unidad_destino
      cs.registerOutParameter(8,  Types.VARCHAR); //p_ades_unidad_destino
      cs.registerOutParameter(9, Types.VARCHAR); //tipo_usuario
      cs.registerOutParameter(10,  OracleTypes.CURSOR); //aplicaciones
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

        cursorAplicaciones = (ResultSet)cs.getObject(10);

        if (cursorAplicaciones == null) {
          System.out.println("El cursor de aplicaciones es vacio");
        } else {
          System.out.println("LISTA DE APLICACIONES");
          String cs_query_app = "{? = call pkg_pc_core.fnc_get_datos_usu_apli(?,?,?,?,?,?,?,?,?)}";
          cs_app = conn.prepareCall(cs_query_app, 1004, 1007);

          while (cursorAplicaciones.next()) {
            ResultSet cursorRoles = null;
            ResultSet cursorPermisos = null;
            ResultSet cursorDelegaciones = null;
            String datosaplicacion = "";
            String ncod_aplicacion = cursorAplicaciones.getString(1);
            if (listaaplicaciones.equalsIgnoreCase(""))
              listaaplicaciones = ncod_aplicacion;
            else {
              listaaplicaciones = listaaplicaciones + "|" + ncod_aplicacion;
            }
            String tipo_aplicacion = cursorAplicaciones.getString(4);
            System.out.println("Aplicacion:" + ncod_aplicacion + "|" + cursorAplicaciones.getString(2) + "|" + cursorAplicaciones.getString(3) + "|" + cursorAplicaciones.getString(4) + "|" + cursorAplicaciones.getString(5));

            String contextoapp = getContextoFromURL(cursorAplicaciones.getString(3));
            String URL= cursorAplicaciones.getString(3).trim();
            
            System.out.println("---------------------------CONTEXTO:" + contextoapp);
            System.out.println("---------------------------URLCOMPLETA:" + URL);
            datosaplicacion = "ncodAplicacion#"
                    + ncod_aplicacion 
                    + "|"  + "adesNombre#" + cursorAplicaciones.getString(2) 
                    + "|" + "adesContexto#" + contextoapp 
                    + "|" + "ncodTipoAplicacion#"  + tipo_aplicacion 
                    + "|" + "nindEstado#" + cursorAplicaciones.getString(5) 
                    + "|"  + "URL#"+URL;

            if (!tipo_aplicacion.equalsIgnoreCase("2"))
            {
              try
              {
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
                if (resultado_app == 1)
                {
                  for (int i = 4; i <= 7; i++) {
                    System.out.println("---------------Dato_app" + i + ":" + cs.getString(i));
                  }

                  datosaplicacion = datosaplicacion 
                          + "|" + "codUnidadAcceso#" + cs_app.getString(4) 
                          + "|" + "adesUnidadAcceso#" + cs_app.getString(5) 
                          + "|" + "codGrupo#" + cs_app.getString(6) 
                          + "|" + "adesGrupo#" + cs_app.getString(7);

                  String lista_codigos_permisos = "";
                  String lista_detalle_permisos = "";
                  cursorPermisos = (ResultSet)cs_app.getObject(8);
                  if (cursorPermisos == null)
                    System.out.println("---------------El cursor de permisos es vacio");
                  else {
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
                    System.out.println("-----------------------Permiso:" + ncod_permiso + "|" + cursorPermisos.getString(2));

                    System.out.println("-----------------------lista de permisos:" + lista_codigos_permisos);
                    System.out.println("-----------------------lista de detalles permisos:" + lista_detalle_permisos);
                  }

                  //ssoToken.setProperty("codigo_permisos_" + contextoapp, lista_codigos_permisos);
                  //ssoToken.setProperty("detalle_permisos_" + contextoapp, lista_detalle_permisos);
                  ssoToken.setProperty("codigo_permisos_" + URL, lista_codigos_permisos);
                  ssoToken.setProperty("detalle_permisos_" + URL, lista_detalle_permisos);
                  System.out.println ("codigo_permisos_" + URL+""+ lista_codigos_permisos);
                  String lista_codigos_roles = "";
                  String lista_detalle_roles = "";

                  cursorRoles = (ResultSet)cs_app.getObject(9);
                  if (cursorRoles == null)
                    System.out.println("---------------El cursor de roles es vacio");
                  else {
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

//                  ssoToken.setProperty("codigo_roles_" + contextoapp, lista_codigos_roles);
//                  ssoToken.setProperty("detalle_roles_" + contextoapp, lista_detalle_roles);
                   ssoToken.setProperty("codigo_roles_" + URL, lista_codigos_roles);
                   ssoToken.setProperty("detalle_roles_" + URL,lista_detalle_roles );
                   System.out.println("codigo_roles_" + URL+""+ lista_codigos_roles);
                  String lista_delegaciones = "";

                  cursorDelegaciones = (ResultSet)cs_app.getObject(10);
                  if (cursorDelegaciones == null) {
                    System.out.println("---------------El cursor de delegaciones es vacio");
                  } else {
                    System.out.println("---------------LISTA DE DELEGACIONES");
                    while (cursorDelegaciones.next()) {
                      String codigo_delegacion = cursorDelegaciones.getString(1);
                      if (!codigo_delegacion.equalsIgnoreCase("-1")) {
                        String delegacion = codigo_delegacion 
                                + "#" + cursorDelegaciones.getString(2) 
                                + "#" + cursorDelegaciones.getString(3) 
                                + "#" + cursorDelegaciones.getString(4) 
                                + "#" + cursorDelegaciones.getString(5) 
                                + "#" + cursorDelegaciones.getString(6) 
                                + "#" + cursorDelegaciones.getString(7) 
                                + "#" + cursorDelegaciones.getString(8) 
                                + "#" + cursorDelegaciones.getString(9);

                        if (lista_delegaciones.equalsIgnoreCase(""))
                          lista_delegaciones = delegacion;
                        else {
                          lista_delegaciones = lista_delegaciones + "|" + delegacion;
                        }
                      }

                    }

                    System.out.println("-----------------------Delegaciones:" + lista_delegaciones);
                    if (!lista_delegaciones.equalsIgnoreCase(""))
                        System.out.println ("------URL Cargaa para delegaciones:"+URL+"y lista:"+lista_delegaciones);
                      //ssoToken.setProperty("delegaciones_" + contextoapp, lista_delegaciones);
                         ssoToken.setProperty("delegaciones_" + URL, lista_delegaciones);
                         System.out.println ("******** Delegaciones_" + URL+""+ lista_delegaciones);
                  }
                }
              }
              catch (SQLException sqlEx)
              {
                sqlEx.printStackTrace();
                throw new SSOException("Error de autenticación:" + sqlEx.toString());
              } finally {
                try {
                  if (cursorPermisos != null) {
                    cursorPermisos.close();
                  }
                  if (cursorRoles != null)
                    cursorRoles.close();
                }
                catch (SQLException e) {
                  e.printStackTrace();
                }
              }
            }
            //ssoToken.setProperty("datos_" + contextoapp, datosaplicacion);
             ssoToken.setProperty("datos_" + URL, datosaplicacion);
             System.out.println ("******** datos_" + URL+""+ datosaplicacion);
            
            System.out.println(".......................datos_aplicacion:" + datosaplicacion);
          }

          ssoToken.setProperty("listaaplicaciones", listaaplicaciones);
          System.out.println ("***************** listaaplicaciones"+ listaaplicaciones);
        }

        cursorIdentificadores = (ResultSet)cs.getObject(11);
        if (cursorIdentificadores == null) {
          System.out.println("El cursor de identificadores es vacio");
        } else {
          System.out.println("LISTA DE IDENTIFICADORES");
          String listaIdentificadores = "";
          while (cursorIdentificadores.next()) {
            System.out.println("Identificador:" + cursorIdentificadores.getString(1));
            if (listaIdentificadores.equalsIgnoreCase(""))
              listaIdentificadores = cursorIdentificadores.getString(1) + "~" + cursorIdentificadores.getString(2);
            else {
              listaIdentificadores = listaIdentificadores + "|" + cursorIdentificadores.getString(1) + "~" + cursorIdentificadores.getString(2);
            }
          }

          ssoToken.setProperty("identificadores", listaIdentificadores);
          System.out.println ("**************identificadores"+listaIdentificadores);
        }
      }
      else {
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
        if (conn != null)
          conn.close();
      }
      catch (SQLException e) {
        e.printStackTrace();
        return false;
      }
    }
    return true;
  }

  public static String getContextoFromURL(String url)
  {
    int veces = 3;
    if (url.indexOf("/") == -1) {
      return url;
    }
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

  private boolean setUserDataFromFile(String username, SSOToken ssoToken) throws SSOException
  {
    System.out.println("Loading user file with:" + username + " and tokenid:" + ssoToken.getTokenID().toString());
    HashMap userdata = cargarFicheroUsuarios();
    System.out.println("User file loaded setting session values");
    Set keys = userdata.keySet();
    Iterator keysit = keys.iterator();
    while (keysit.hasNext()) {
      String key = (String)keysit.next();
      ssoToken.setProperty(key, (String)userdata.get(key));
      System.out.println("setting session:<key>:" + key + " <value>:" + (String)userdata.get(key));
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

  private HashMap<String, String> cargarFicheroUsuarios()
  {
    HashMap hMapUsuarios = null;
    Properties prop = new Properties();

    System.out.println("loading file........");
    try {
      FileInputStream userdata = new FileInputStream("/home/oracle/properties/usuario.properties");
      System.out.println("resource obtained, trying to load in properties....");
      prop.load(userdata);
      System.out.println("Properties file loaded:" + prop.toString());
    }
    catch (IOException e) {
      System.out.println("Exception loading file:" + e);
    }

    hMapUsuarios = new HashMap();
    System.out.println("Obtaining enumeration from properties variable");
    Enumeration e = prop.keys();
    System.out.println("Enumeration created with keys:" + e.toString());

    while (e.hasMoreElements()) {
      String strKey = (String)e.nextElement();
      hMapUsuarios.put(strKey, prop.getProperty(strKey));
      System.out.println("Establishing hashMap with file values:<key>:" + strKey + "<value>:" + prop.getProperty(strKey));
    }
    System.out.println("returning hmapusuarios:" + hMapUsuarios);
    return hMapUsuarios;
  }
}
