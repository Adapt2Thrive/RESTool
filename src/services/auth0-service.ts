import createAuth0Client, { User } from "@auth0/auth0-spa-js";

const auth0Promise = createAuth0Client({
    domain: process.env.REACT_APP_AUTH0_DOMAIN || "",
    client_id: process.env.REACT_APP_AUTH0_CLIENT_ID || "",
    redirect_uri: `${window.location.origin}`,
    cacheLocation: "localstorage",
    audience: process.env.REACT_APP_AUTH0_AUDIENCE
});

const CODE_RE = /[?&]code=[^&]+/;
const STATE_RE = /[?&]state=[^&]+/;
const ERROR_RE = /[?&]error=[^&]+/;

export const hasAuthParams = (searchParams = window.location.search): boolean =>
    (CODE_RE.test(searchParams) || ERROR_RE.test(searchParams)) &&
    STATE_RE.test(searchParams);

async function getUserAndTokenOrRedirectToLogin(): Promise<{ user: User, token: string } | null> {
    const auth0 = await auth0Promise;
    try {
        const hasAuthParamsCached = hasAuthParams();
        if (hasAuthParamsCached) {
            // if the url contains code & state parameters, parse the authentication result from auth0
            const { appState } = await auth0.handleRedirectCallback();

            window.location.hash = window.location.hash; // eslint-disable-line no-self-assign
            // replace the window history so users can safely click "back" without triggering a new token
            window.history.replaceState(
                {},
                document.title,
                appState?.targetUrl || window.location.pathname
            );

            const urlBeforeLogin = sessionStorage.getItem('urlBeforeLogin');
            if (urlBeforeLogin) {
                sessionStorage.removeItem('urlBeforeLogin');
                window.history.pushState({}, document.title, urlBeforeLogin);
            }
        }

        // checkSession() will trigger internally a getTokenSilently() and populate the token cache
        // it seems we need checkSession() in order to login so getUser() returns a user. 
        // in theory, auth0.getTokenSilently() should (login and) return the token right away, but if the user is not logged in, auth0 throws a "login required" error
        await auth0.checkSession();
        const user = await auth0.getUser();

        if (!user) {
            // if for some reason the user does not exist, but we _had_ a code and state, let's logout. 
            // However, the user probably wants a screen complaining that something went wrong
            if (hasAuthParamsCached) {
                auth0.logout();
            }

            sessionStorage.setItem('urlBeforeLogin', window.location.pathname);

            // if there's no user, we want to login right away - yup, there's no login page button
            await auth0.loginWithRedirect();
        } else {
            // if the user exists, we want to get the API token, in order to make api calls to coaching-api.*
            const token: string = await auth0.getTokenSilently();
            return { user, token }
        }
    } catch (error) {
        console.log(error);
    }
    return null;
};

const logout = async (): Promise<void> => {
    const auth0 = await auth0Promise;
    return auth0.logout({ returnTo: 'https://localhost:3000' });
};

const getLogoutUrl = async (): Promise<string> => {
    const auth0 = await auth0Promise;
    return auth0.buildLogoutUrl();
};

export {
    getUserAndTokenOrRedirectToLogin,
    logout,
    getLogoutUrl
}