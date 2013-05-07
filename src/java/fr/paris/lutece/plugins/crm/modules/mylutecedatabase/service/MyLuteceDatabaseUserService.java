/*
 * Copyright (c) 2002-2013, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.crm.modules.mylutecedatabase.service;

import fr.paris.lutece.plugins.crm.modules.mylutece.service.IMyLuteceUserService;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.DatabaseHome;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.DatabaseUser;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.business.DatabaseUserHome;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.DatabaseAnonymizationService;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.DatabasePlugin;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.DatabaseService;
import fr.paris.lutece.plugins.mylutece.modules.database.authentication.service.key.DatabaseUserKeyService;
import fr.paris.lutece.plugins.mylutece.service.IAnonymizationService;
import fr.paris.lutece.plugins.mylutece.service.attribute.MyLuteceUserFieldService;
import fr.paris.lutece.portal.service.admin.AdminAuthenticationService;
import fr.paris.lutece.portal.service.i18n.I18nService;
import fr.paris.lutece.portal.service.mail.MailService;
import fr.paris.lutece.portal.service.plugin.Plugin;
import fr.paris.lutece.portal.service.plugin.PluginService;
import fr.paris.lutece.portal.service.template.AppTemplateService;
import fr.paris.lutece.portal.service.util.AppPathService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;
import fr.paris.lutece.util.html.HtmlTemplate;
import fr.paris.lutece.util.password.PasswordUtil;

import org.apache.commons.lang.StringUtils;

import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;

import javax.servlet.http.HttpServletRequest;


/**
 *
 * MyLuteceDirectoryUserService
 *
 */
public class MyLuteceDatabaseUserService implements IMyLuteceUserService<Collection<DatabaseUser>>
{
    // PROPERTIES
    private static final String PROPERTY_NO_REPLY_EMAIL = "mail.noreply.email";

    // MESSAGE
    private static final String MESSAGE_EMAIL_SUBJECT = "module.mylutece.database.forgot_password.email.subject";

    // MARKS
    private static final String MARK_NEW_PASSWORD = "new_password";
    private static final String MARK_LOGIN_URL = "login_url";

    // TEMPLATES
    private static final String TEMPLATE_EMAIL_FORGOT_PASSWORD = "admin/plugins/mylutece/modules/database/email_forgot_password.html";
    @Inject
    @Named( DatabaseAnonymizationService.BEAN_DATABASE_ANONYMIZATION_SERVICE )
    private IAnonymizationService _anonymizationService;

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<DatabaseUser> getMyLuteceUserByUserGuid( String strUserGuid )
    {
        return DatabaseUserHome.findDatabaseUsersListForLogin( strUserGuid,
            PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME ) );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void doRemoveMyLuteceUser( Collection<DatabaseUser> listMyLuteceUsers, HttpServletRequest request,
        Locale locale )
    {
        if ( ( listMyLuteceUsers != null ) && !listMyLuteceUsers.isEmpty(  ) )
        {
            Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );

            for ( DatabaseUser user : listMyLuteceUsers )
            {
                DatabaseUserHome.remove( user, plugin );
                DatabaseHome.removeGroupsForUser( user.getUserId(  ), plugin );
                DatabaseHome.removeRolesForUser( user.getUserId(  ), plugin );
                MyLuteceUserFieldService.doRemoveUserFields( user.getUserId(  ), request, locale );
                DatabaseUserKeyService.getService(  ).removeByIdUser( user.getUserId(  ) );
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void doAnonymizeMyLuteceUser( Collection<DatabaseUser> listMyLuteceUsers, HttpServletRequest request,
        Locale locale )
    {
        if ( ( listMyLuteceUsers != null ) && !listMyLuteceUsers.isEmpty(  ) )
        {
            for ( DatabaseUser user : listMyLuteceUsers )
            {
                _anonymizationService.anonymizeUser( user.getUserId(  ), locale );
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void doReinitPassword( Collection<DatabaseUser> listMyLuteceUsers, HttpServletRequest request, Locale locale )
    {
        if ( ( listMyLuteceUsers != null ) && !listMyLuteceUsers.isEmpty(  ) )
        {
            Plugin plugin = PluginService.getPlugin( DatabasePlugin.PLUGIN_NAME );

            for ( DatabaseUser user : listMyLuteceUsers )
            {
                // Makes password
                String strPassword = PasswordUtil.makePassword(  );
                DatabaseService.getService(  ).doModifyPassword( user, strPassword, plugin );

                if ( StringUtils.isNotBlank( user.getEmail(  ) ) )
                {
                    // Sends password by e-mail
                    String strSenderEmail = AppPropertiesService.getProperty( PROPERTY_NO_REPLY_EMAIL );
                    String strEmailSubject = I18nService.getLocalizedString( MESSAGE_EMAIL_SUBJECT, locale );
                    Map<String, Object> model = new HashMap<String, Object>(  );
                    model.put( MARK_NEW_PASSWORD, strPassword );
                    model.put( MARK_LOGIN_URL,
                        AppPathService.getBaseUrl( request ) +
                        AdminAuthenticationService.getInstance(  ).getLoginPageUrl(  ) );

                    HtmlTemplate template = AppTemplateService.getTemplate( TEMPLATE_EMAIL_FORGOT_PASSWORD, locale,
                            model );

                    MailService.sendMailHtml( user.getEmail(  ), strSenderEmail, strSenderEmail, strEmailSubject,
                        template.getHtml(  ) );
                }
            }
        }
    }
}
