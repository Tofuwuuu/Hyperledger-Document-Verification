import axios from 'axios';
import { 
  getAuthTokens, 
  storeAuthTokens, 
  clearAuthTokens,
  isRememberedSession 
} from '../utils/authUtils';
import { API_URL as CONFIG_API_URL } from '../config';
import { prepareProfileData } from '../utils/profile-helpers';

// Single source of truth (see `src/config.js`)
export const API_URL = CONFIG_API_URL;

export const api = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest'  // Help prevent CSRF attacks
  }
});

api.interceptors.request.use(
  (config) => {
    config.withCredentials = true;

    const token = localStorage.getItem('token');
    if (token && !config.headers.Authorization) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => {
    const csrfToken = response.headers['x-csrf-token'];
    if (csrfToken) {
      localStorage.setItem('csrf_token', csrfToken);
    }
    
    return response;
  },
  async (error) => {
    if (import.meta.env.MODE === 'development') {
      console.error(`❌ API Error [${error.response?.status || 'Network Error'}]`, { 
        message: error.message,
        response: error.response,
        config: error.config
      });
    }

    if (error.response) {
      const statusCode = error.response.status;
      
      // If we get a 401, check if the token is expired
      if (statusCode === 401) {
        // Handle token expiration (add refresh token logic if needed)
      }

      error.isNetworkError = false;
      error.statusCode = statusCode;
      error.isAuthError = statusCode === 401;
      error.isForbidden = statusCode === 403;
      error.isServerError = statusCode >= 500;
    } else if (error.request) {
      console.error('Network error - no response received');
      error.isNetworkError = true;
      error.message = 'Unable to connect to the server. Please check your internet connection.';
    }

    return Promise.reject(error);
  }
);

export const apiService = {
  get: async (url, config = {}) => {
    try {
      return await api.get(url, config);
    } catch (error) {
      handleApiError(error, 'GET', url);
      throw error;
    }
  },
  post: async (url, data, config = {}) => {
    try {
      return await api.post(url, data, config);
    } catch (error) {
      handleApiError(error, 'POST', url);
      throw error;
    }
  },
  put: async (url, data, config = {}) => {
    try {
      return await api.put(url, data, config);
    } catch (error) {
      handleApiError(error, 'PUT', url);
      throw error;
    }
  },
  delete: async (url, config = {}) => {
    try {
      return await api.delete(url, config);
    } catch (error) {
      handleApiError(error, 'DELETE', url);
      throw error;
    }
  },
  // Specific method for CORS-sensitive endpoints
  withCORS: async (method, url, data = null, config = {}) => {
    if (!config.headers) {
      config.headers = {};
    }
    
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    const csrfToken = localStorage.getItem('csrf_token');
    if (csrfToken && !config.headers['X-CSRF-Token']) {
      config.headers['X-CSRF-Token'] = csrfToken;
    }
    
    const mergedConfig = {
      ...config,
      timeout: config.timeout || 15000,
      withCredentials: true,
      headers: {
        ...(config.headers || {}),
        'X-Requested-With': 'XMLHttpRequest'
      }
    };
    
    if (config.signal) {
      mergedConfig.signal = config.signal;
    }
    
    let retries = 0;
    const maxRetries = 2;
    
    while (retries <= maxRetries) {
      try {
        let response;
        if (method.toLowerCase() === 'get') {
          response = await api.get(url, mergedConfig);
        } else if (method.toLowerCase() === 'post') {
          response = await api.post(url, data, mergedConfig);
        } else if (method.toLowerCase() === 'put') {
          response = await api.put(url, data, mergedConfig);
        } else if (method.toLowerCase() === 'delete') {
          response = await api.delete(url, mergedConfig);
        } else {
          throw new Error(`Unsupported method: ${method}`);
        }
        
        return response;
      } catch (error) {
        console.error(`API error (attempt ${retries + 1}/${maxRetries + 1}):`, error);
        
        if (error.name === 'AbortError' || error.code === 'ECONNABORTED') {
          console.error('Request aborted or timed out');
          error.isTimeout = true;
          throw error; // Don't retry timeouts or aborted requests
        }
        
        const isCsrfError = error.response?.data?.detail?.includes('CSRF token');
        if (isCsrfError && retries < maxRetries) {
          console.warn('CSRF error detected, will try to get a new token...');
          
          try {
            const tokenResponse = await api.get('/auth/csrf-token');
            if (tokenResponse.data && tokenResponse.data.csrf_token) {
              mergedConfig.headers['X-CSRF-Token'] = tokenResponse.data.csrf_token;
              retries++;
              await new Promise(resolve => setTimeout(resolve, 500));
              continue;
            }
          } catch (tokenError) {
            console.error('Failed to get new CSRF token:', tokenError);
          }
        }
        
        const isCORSError = error.message && (
          error.message.includes('CORS') || 
          (error.response && error.response.status === 0)
        );
        
        if (isCORSError && retries < maxRetries) {
          console.warn(`CORS error detected, retrying (${retries + 1}/${maxRetries})...`);
          retries++;
          await new Promise(resolve => setTimeout(resolve, 1000));
          continue;
        }
        
        throw error;
      }
    }
  }
};

function handleApiError(error, method, url, isCORSRequest = false) {
  if (error.isNetworkError) {
    console.error(`Network error detected in API call: ${error.message}`);
  } else if (error.response) {
    console.error(`API ${method} ${url} failed with status ${error.response.status}:`, 
      error.response.data);
      
    if (isCORSRequest && !error.response.headers['access-control-allow-origin']) {
      console.error('Possible CORS error - missing Access-Control-Allow-Origin header');
    }
  } else {
    console.error(`API ${method} ${url} failed:`, error.message);
  }
}

export const authService = {
  reloadUserWithFreshData: async () => {
    localStorage.removeItem('user_verification');
    
    const { accessToken } = getAuthTokens();
    
    if (!accessToken) {
      return null;
    }

    try {
      const timestamp = new Date().getTime();
      
      const response = await api.get(`/auth/me?t=${timestamp}`, {
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      });
      
      const userData = response.data;
      localStorage.setItem('user', JSON.stringify(userData));
      
      return userData;
    } catch (error) {
      return handleApiError(error, 'reloadUserWithFreshData');
    }
  },
  
  getCsrfToken: async () => {
    try {
      const response = await api.get('/auth/csrf-token');
      if (response.data && response.data.csrf_token) {
        localStorage.setItem('csrf_token', response.data.csrf_token);
        return response.data.csrf_token;
      }
      return null;
    } catch (error) {
      console.error('Error getting CSRF token:', error);
      // Don't throw here as this is a non-critical operation
      return null;
    }
  },
  
  login: async (credentials) => {
    try {
      const { remember } = credentials;
      const payload = {
        email: credentials.email,
        password: credentials.password,
        remember: remember !== undefined ? remember : false
      };
      
      const loginUrl = `${API_URL}/auth/login`;

      const loginResponse = await axios.post(loginUrl, payload, {
        headers: {
          'Content-Type': 'application/json',
        }
      });

      // MFA on: the password step only returns a short-lived pending token.
      if (loginResponse.data?.mfa_required && loginResponse.data?.mfa_token) {
        return loginResponse.data;
      }
      
      if (loginResponse.data?.success && loginResponse.data?.user) {
        // Simple local auth state (no JWT in this mode).
        localStorage.setItem('user', JSON.stringify(loginResponse.data.user));
        localStorage.setItem('simple_auth', 'true');
        localStorage.removeItem('token');
        return loginResponse.data;
      } else {
        throw new Error('Login failed: invalid response payload');
      }
    } catch (error) {
      // Preserve the original error details, including headers and response data
      const enhancedError = new Error(error.response?.data?.detail || error.message || 'Login failed');
      enhancedError.originalError = error;
      enhancedError.response = error.response;
      enhancedError.status = error.response?.status;
      enhancedError.headers = error.response?.headers;
      
      console.error('[LOGIN] Error message:', enhancedError.message);
      console.error('[LOGIN] Error status:', enhancedError.status);
      throw enhancedError; // Throw the enhanced error to be caught by the LoginPage
    }
  },

  // Second login step: trade the pending token and a 6-digit code for a session.
  verifyMfa: async (mfaToken, code, remember = false) => {
    try {
      const response = await axios.post(
        `${API_URL}/auth/mfa/verify`,
        { mfa_token: mfaToken, code, remember },
        { headers: { 'Content-Type': 'application/json' } }
      );
      if (response.data?.user) {
        localStorage.setItem('user', JSON.stringify(response.data.user));
        localStorage.setItem('simple_auth', 'true');
      }
      return response.data;
    } catch (error) {
      const enhancedError = new Error(error.response?.data?.detail || error.message || 'Verification failed');
      enhancedError.response = error.response;
      enhancedError.status = error.response?.status;
      throw enhancedError;
    }
  },
  
  register: async (userData) => {
    try {
      const registerUrl = `${API_URL}/auth/register`;

      // Plain axios: skip the shared interceptors for the public register call.
      const response = await axios({
        method: 'post',
        url: registerUrl,
        data: userData,
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 10000
      });
      
      return response.data;
    } catch (error) {
      console.error('Registration request failed:', error.message);
      if (error.response) {
        console.error('Error response data:', error.response.data);
        console.error('Error response status:', error.response.status);
      } else if (error.request) {
        console.error('No response received:', error.request);
        
        if (error.message.includes('Network Error')) {
          error.corsError = true;
        }
      }
      throw error;
    }
  },
  
  refreshToken: async () => {
    const { refreshToken } = getAuthTokens();
    if (!refreshToken) {
      return Promise.reject('No refresh token available');
    }
    
    try {
      const apiUrlBase = API_URL.endsWith('/') ? API_URL.slice(0, -1) : API_URL;
      const refreshUrl = `${apiUrlBase}/auth/refresh`;
      
      const response = await axios.post(refreshUrl);
      
      if (response.data.access_token) {
        storeAuthTokens(
          {
            accessToken: response.data.access_token,
            refreshToken: response.data.refresh_token
          },
          isRememberedSession()
        );
      }
      
      return response.data;
    } catch (error) {
      return handleApiError(error, 'refreshToken');
    }
  },
  
  logout: async () => {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout API call failed:', error);
    } finally {
      // Clear local storage regardless of API success/failure
      clearAuthTokens();
    }
  },
  
  getCurrentUser: async () => {
    const { accessToken } = getAuthTokens();
    
    if (!accessToken) {
      return null;
    }

    try {
      const response = await api.get('/auth/me');
      return response.data;
    } catch (error) {
      return handleApiError(error, 'getCurrentUser');
    }
  },

  checkAuth: async () => {
    try {
      const response = await api.get('/auth/me');
      return { isAuthenticated: true, user: response.data };
    } catch (error) {
      if (error.status === 401) {
        clearAuthTokens();
      }
      return { isAuthenticated: false, user: null };
    }
  },

  // MFA methods. These rethrow so the setup screen can show the right message.
  getMFAStatus: async () => {
    try {
      const response = await api.get('/auth/mfa/status');
      return response.data;
    } catch (error) {
      handleApiError(error, 'getMFAStatus');
      throw error;
    }
  },

  // Returns the secret and otpauth URI. MFA stays off until enableMFA gets a correct code.
  setupMFA: async () => {
    try {
      const response = await api.post('/auth/mfa/setup', { type: 'totp' });
      return response.data;
    } catch (error) {
      handleApiError(error, 'setupMFA');
      throw error;
    }
  },

  enableMFA: async (verificationCode) => {
    try {
      const response = await api.post('/auth/mfa/enable', { verification_code: verificationCode });
      return response.data;
    } catch (error) {
      handleApiError(error, 'enableMFA');
      throw error;
    }
  },

  // Turning MFA off needs a current code from the authenticator app.
  disableMFA: async (code) => {
    try {
      const response = await api.post('/auth/mfa/disable', { code });
      return response.data;
    } catch (error) {
      handleApiError(error, 'disableMFA');
      throw error;
    }
  },

  setSecurityQuestions: async (questionsData) => {
    try {
      const response = await api.post('/auth/set-security-questions', questionsData);
      return response.data;
    } catch (error) {
      return handleApiError(error, 'setSecurityQuestions');
    }
  },
  
  getSecurityQuestions: async (email) => {
    try {
      const response = await api.get(`/auth/security-questions/${email}`);
      return response.data;
    } catch (error) {
      return handleApiError(error, 'getSecurityQuestions');
    }
  },
  
  verifySecurityQuestions: async (data) => {
    try {
      const response = await api.post('/auth/verify-security-questions', data);
      return response.data;
    } catch (error) {
      return handleApiError(error, 'verifySecurityQuestions');
    }
  },
};

export const alumniService = {
  createProfileReliable: async (profileData) => {
    try {
      // Normalize profile data and attach user_id before saving
      const preparedData = await prepareProfileData(profileData);
      
      const response = await api.post('/alumni/simple', preparedData);
      
      if (response.data.success) {
        return response;
          } else {
        console.error('Server reported error in profile creation:', response.data.message);
        throw new Error(response.data.message);
      }
    } catch (error) {
      console.error('Error creating alumni profile (reliable endpoint):', error.message);
      throw error;
    }
  },
  
  updateProfileReliable: async (profileData) => {
    try {
      const alumniId = profileData.id;
      
      if (!alumniId || alumniId === 'undefined') {
        console.error('Invalid or missing alumni ID:', alumniId);
        throw new Error('Alumni ID is undefined or invalid. Cannot update profile.');
      }

      const response = await api.put(`/alumni/${alumniId}/simple`, profileData);
      
      if (response.data.success) {
        return {
          data: {
            ...profileData,
            _id: alumniId
          }
        };
      } else {
        console.error('Server reported error in profile update:', response.data.message);
        throw new Error(response.data.message);
      }
    } catch (error) {
      console.error('Error updating alumni profile (reliable endpoint):', error.message);
      throw error;
    }
  },
  
  createProfile: async (profileData) => {
    try {
      // Normalize profile data and attach user_id before saving
      const preparedData = await prepareProfileData(profileData);

      try {
        const existingProfile = await alumniService.getAlumniByUserId(preparedData.user_id);
        if (existingProfile && existingProfile.data && existingProfile.status !== 404) {
          console.warn('Alumni profile already exists for this user. Updating existing profile instead.');
          
          return alumniService.updateProfile({
            ...preparedData,
            id: existingProfile.data._id
          });
        }
      } catch {
        // If there's an error checking for an existing profile, just continue with create
      }
      
      try {
        return await alumniService.createProfileReliable(preparedData);
      } catch (reliableError) {
        if (reliableError.message && reliableError.message.includes('already exists')) {
          console.warn('Profile already exists error from reliable endpoint. Trying to get and update profile instead.');
          
          try {
            const existingProfile = await alumniService.getAlumniByUserId(preparedData.user_id);
            if (existingProfile && existingProfile.data) {
              return alumniService.updateProfile({
                ...preparedData,
                id: existingProfile.data._id
              });
            }
          } catch (getProfileError) {
            console.error('Failed to get existing profile:', getProfileError.message);
          }
        }
        
        console.warn('Reliable endpoint failed, falling back to standard endpoint:', reliableError.message);
      }
      
      try {
        return await api.post('/alumni', preparedData);
      } catch (standardError) {
        // If standard endpoint fails with 405, try again with the simplified endpoint
        if (standardError.response && standardError.response.status === 405) {
          console.warn('Standard endpoint returned 405, trying simplified endpoint as last resort');
          return alumniService.createProfileReliable(preparedData);
        }
        throw standardError;
      }
    } catch (error) {
      console.error('Error creating alumni profile:', error.message);
      throw error;
    }
  },
  
  updateProfile: async (profileData) => {
    try {
      try {
        return await alumniService.updateProfileReliable(profileData);
      } catch (reliableError) {
        console.warn('Reliable endpoint failed, falling back to standard endpoint:', reliableError.message);
      }
      
    const alumniId = profileData.id;
    
      if (!alumniId || alumniId === 'undefined') {
        console.error('Invalid or missing alumni ID:', alumniId);
        throw new Error('Alumni ID is undefined or invalid. Cannot update profile.');
      }

      return await api.put(`/alumni/${alumniId}`, profileData);
    } catch (error) {
      console.error('Error updating alumni profile:', error.message);
      throw error;
    }
  },
  
  // The catch here never fired: the promise was returned un-awaited.
  getProfile: async (alumniId) => api.get(`/alumni/${alumniId}`),
  
  getAlumniByUserId: async (userId) => {
    try {
      return await apiService.withCORS('get', `/alumni/user/${userId}`);
    } catch (corsError) {
      console.warn('Error with CORS-enabled request:', corsError);
    }
    try {
      return await api.get(`/alumni/user/${userId}`);
    } catch (directError) {
      console.error(`Error fetching alumni profile for user ${userId}:`, directError);
      // No profile yet is normal during onboarding; callers check status === 404.
      if (directError.response?.status === 404) {
        return { status: 404, statusText: 'Not Found', data: null };
      }
      throw directError;
    }
  },
  
  uploadProfilePicture: async (alumniId, file) => {
    try {
      const formData = new FormData();
      formData.append('profile_picture', file);
      
      const response = await axios({
        method: 'post',
        url: `${API_URL}/alumni/${alumniId}/profile-picture`,
        data: formData,
        headers: {
          'Content-Type': 'multipart/form-data',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        timeout: 30000
      });
      
      return response;
    } catch (error) {
      console.error(`Error uploading profile picture for ${alumniId}:`, error.message);
      if (error.response) {
        console.error('Error response data:', error.response.data);
        console.error('Error response status:', error.response.status);
      } else if (error.request) {
        console.error('No response received:', error.request);
      }
      throw error;
    }
  },
  
  getAllAlumni: async (params = {}) => {
    try {
      return await api.get('/alumni/list', { params });
    } catch (listError) {
      console.error('Simplified alumni endpoint failed:', listError);
    }
    try {
      return await api.get('/alumni', { params });
    } catch (error) {
      console.error('Error fetching alumni list (all attempts failed):', error);
      
      return {
        data: {
          results: [],
          total: 0,
          limit: params.limit || 10,
          offset: params.offset || 0
        }
      };
    }
  },
};

export const documentService = {
  uploadDocument: async (data) => {
    const formData = new FormData();
    formData.append('alumni_id', data.alumni_id);
    formData.append('document_type', data.document_type);
    formData.append('title', data.title);
    
    if (data.description) {
      formData.append('description', data.description);
    }
    
    formData.append('file', data.file);
    
    return api.post('/documents/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },
  
  getAlumniDocuments: async (alumniId) => {
    return api.get(`/documents/alumni/${alumniId}`);
  },
  
  getDocument: async (documentId) => {
    return api.get(`/documents/${documentId}`);
  },

  previewDocument: async (documentId) => {
    return api.get(`/documents/${documentId}/preview`, {
      responseType: 'blob',
    });
  },

  downloadDocument: async (documentId) => {
    return api.get(`/documents/${documentId}/download`, {
      responseType: 'blob',
    });
  },
  
  deleteDocument: async (documentId) => {
    return api.delete(`/documents/${documentId}`);
  },
  
  getAllPendingDocuments: async () => {
    return api.get('/documents/pending/all');
  },
};

export const verificationService = {
  verifyDocument: async (documentId, hash) => {
    return api.post('/verification/blockchain/verify', {
      document_id: documentId,
      hash: hash
    });
  },
  
  storeDocument: async (documentId, hash, metadata = {}) => {
    return api.post('/verification/blockchain/store', {
      document_id: documentId,
      hash: hash,
      metadata: metadata
    });
  },
  
  rejectDocument: async (documentId, reason) => {
    return api.post(`/documents/${documentId}/reject`, { reason });
  },
  
  getDocumentHistory: async (documentId) => {
    return api.get(`/verification/blockchain/history/${documentId}`);
  },
  
  verifyByFile: async (documentId, file) => {
    const formData = new FormData();
    if (documentId) {
      formData.append('document_id', documentId);
    }
    formData.append('file', file);
    
    return api.post('/verification/blockchain/verify-file', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  }
};

export const adminUserService = {
  getAllAdminUsers: async (page = 1, limit = 10, signal) => {
    try {
      return await api.get('/admin/users', { 
        params: { page, limit },
        timeout: 30000,
        signal
      });
    } catch (error) {
      // Don't log or throw error if request was intentionally aborted
      if (error.name === 'CanceledError' || error.name === 'AbortError' || error.code === 'ERR_CANCELED') {
        return { data: { items: [], meta: { total: 0, totalPages: 0 } } };
      }
      
      console.error('Error fetching admin users:', error);
      throw new Error(error.response?.data?.message || 'Failed to fetch admin users');
    }
  },

  getPendingVerificationUsers: async (signal, status = 'pending') => {
    try {
      return await api.get('/admin/users/pending-verification', {
        params: { status },
        timeout: 30000,
        signal
      });
    } catch (error) {
      if (error.name === 'CanceledError' || error.name === 'AbortError' || error.code === 'ERR_CANCELED') {
        return { data: [] };
      }

      console.error('Error fetching pending verification users:', error);
      throw new Error(error.response?.data?.detail || 'Failed to fetch pending verification users');
    }
  },

  verifyPendingUser: async (userId, adminNotes = '') => {
    try {
      return await api.post(`/admin/users/${userId}/verify`, {
        admin_notes: adminNotes || null
      }, { timeout: 10000 });
    } catch (error) {
      console.error(`Error verifying user ${userId}:`, error);
      throw new Error(error.response?.data?.detail || 'Failed to verify user');
    }
  },

  rejectPendingUser: async (userId, adminNotes = '') => {
    try {
      return await api.post(`/admin/users/${userId}/reject`, {
        admin_notes: adminNotes || null
      }, { timeout: 10000 });
    } catch (error) {
      console.error(`Error rejecting user ${userId}:`, error);
      throw new Error(error.response?.data?.detail || 'Failed to reject user');
    }
  },
  
  getAdminUser: async (userId) => {
    try {
      return await api.get(`/admin/users/${userId}`, { timeout: 10000 });
    } catch (error) {
      console.error(`Error fetching admin user ${userId}:`, error);
      throw new Error(error.response?.data?.message || 'Failed to fetch admin user');
    }
  },
  
  createAdminUser: async (userData) => {
    try {
      return await api.post('/admin/users', userData, { timeout: 10000 });
    } catch (error) {
      console.error('Error creating admin user:', error);
      if (error.response) {
        console.error('Error response data:', error.response.data);
        
        // Ensure we're not passing complex objects as error messages
        if (error.response.data && typeof error.response.data.detail === 'object') {
          const enhancedError = new Error(
            error.response.status === 422 
              ? 'Validation failed. Please check the form fields.' 
              : 'Failed to create admin user'
          );
          enhancedError.response = error.response;
          enhancedError.status = error.response.status;
          enhancedError.responseData = error.response.data;
          throw enhancedError;
        }
      }
      throw error;
    }
  },
  
  updateAdminUser: async (userId, userData) => {
    try {
      return await api.put(`/admin/users/${userId}`, userData, { timeout: 10000 });
    } catch (error) {
      console.error(`Error updating admin user ${userId}:`, error);
      if (error.response) {
        console.error('Error response data:', error.response.data);
        
        // Ensure we're not passing complex objects as error messages
        if (error.response.data && typeof error.response.data.detail === 'object') {
          const enhancedError = new Error(
            error.response.status === 422 
              ? 'Validation failed. Please check the form fields.' 
              : `Failed to update admin user ${userId}`
          );
          enhancedError.response = error.response;
          enhancedError.status = error.response.status;
          enhancedError.responseData = error.response.data;
          throw enhancedError;
        }
      }
      throw error;
    }
  },
  
  deleteAdminUser: async (userId) => {
    try {
      return await api.delete(`/admin/users/${userId}`, { timeout: 10000 });
    } catch (error) {
      console.error(`Error deleting admin user ${userId}:`, error);
      throw new Error(error.response?.data?.message || 'Failed to delete admin user');
    }
  },
  
  updateUserRole: async (userId, roleData) => {
    try {
      return await api.put(`/admin/users/${userId}/role`, roleData, { timeout: 10000 });
    } catch (error) {
      console.error(`Error updating role for user ${userId}:`, error);
      throw new Error(error.response?.data?.message || 'Failed to update user role');
    }
  },
  
  getRoles: async () => {
    try {
      return await api.get('/admin/roles', {
        params: { page: 1, limit: 100 },
        timeout: 10000
      });
    } catch {
      return { data: { items: [], meta: { total: 0, totalPages: 0 } } };
    }
  }
};

export const roleService = {
  getAllRoles: async (page = 1, limit = 10, signal, retryCount = 2) => {
    try {
      return await api.get('/admin/roles', { 
        params: { page, limit },
        timeout: 10000,
        signal
      });
    } catch (error) {
      // Retry network failures, never aborts.
      if (retryCount > 0 && error.name !== 'AbortError' && 
         (error.code === 'ECONNABORTED' || error.message.includes('Network Error'))) {
        await new Promise(resolve => setTimeout(resolve, 500));
        return roleService.getAllRoles(page, limit, signal, retryCount - 1);
      }
      
      throw error;
    }
  },
  
  getRole: async (roleId) => {
    try {
      return await api.get(`/admin/roles/${roleId}`, { timeout: 10000 });
    } catch (error) {
      console.error(`Error fetching role ${roleId}:`, error);
      throw new Error(error.response?.data?.message || 'Failed to fetch role');
    }
  },
  
  createRole: async (roleData) => {
    try {
      return await api.post('/admin/roles', roleData, { timeout: 10000 });
    } catch (error) {
      console.error('Error creating role:', error);
      throw new Error(error.response?.data?.message || 'Failed to create role');
    }
  },
  
  updateRole: async (roleId, roleData) => {
    try {
      return await api.put(`/admin/roles/${roleId}`, roleData, { timeout: 10000 });
    } catch (error) {
      console.error(`Error updating role ${roleId}:`, error);
      throw new Error(error.response?.data?.message || 'Failed to update role');
    }
  },
  
  deleteRole: async (roleId) => {
    try {
      return await api.delete(`/admin/roles/${roleId}`, { timeout: 10000 });
    } catch (error) {
      console.error(`Error deleting role ${roleId}:`, error);
      throw new Error(error.response?.data?.message || 'Failed to delete role');
    }
  },
  
  getPermissions: async (signal) => {
    try {
      return await api.get('/admin/permissions', { 
        timeout: 10000,
        signal
      });
    } catch (error) {
      // Don't throw error if request was aborted
      if (error.name === 'AbortError' || error.name === 'CanceledError' || error.code === 'ERR_CANCELED' || error.code === 'ECONNABORTED') {
        return { data: [] };
      }
      console.error('Error fetching permissions:', error);
      throw new Error(error.response?.data?.message || 'Failed to fetch permissions');
    }
  },
  
  assignPermission: async (roleId, permissionData) => {
    try {
      return await api.post(`/admin/roles/${roleId}/permissions`, permissionData, { timeout: 10000 });
    } catch (error) {
      console.error(`Error assigning permission to role ${roleId}:`, error);
      throw new Error(error.response?.data?.message || 'Failed to assign permission');
    }
  },
  
  removePermission: async (roleId, permissionId) => {
    try {
      return await api.delete(`/admin/roles/${roleId}/permissions/${permissionId}`, { timeout: 10000 });
    } catch (error) {
      console.error(`Error removing permission ${permissionId} from role ${roleId}:`, error);
      throw new Error(error.response?.data?.message || 'Failed to remove permission');
    }
  }
};

export const adminVerificationService = {
  getVerificationRequests: async (status = 'pending') => {
    try {
      return await api.get(`/admin/verifications?status=${status}`, { timeout: 10000 });
    } catch (error) {
      console.error('Error fetching verification requests:', error);
      throw new Error(error.response?.data?.message || 'Failed to fetch verification requests');
    }
  },
  
  approveVerification: async (documentId, notes = 'Verified and approved.') => {
    try {
      return await api.post(`/admin/verifications/${documentId}/approve`, { 
        admin_notes: notes 
      }, { timeout: 10000 });
    } catch (error) {
      console.error(`Error approving verification ${documentId}:`, error);
      throw new Error(error.response?.data?.detail || error.response?.data?.message || 'Failed to approve verification');
    }
  },
  
  rejectVerification: async (documentId, notes) => {
    try {
      return await api.post(`/admin/verifications/${documentId}/reject`, { 
        admin_notes: notes || 'Document rejected due to verification issues.' 
      }, { timeout: 10000 });
    } catch (error) {
      console.error(`Error rejecting verification ${documentId}:`, error);
      throw new Error(error.response?.data?.message || 'Failed to reject verification');
    }
  },

  previewDocument: async (documentId) => {
    return api.get(`/documents/${documentId}/preview`, {
      responseType: 'blob',
      timeout: 10000,
    });
  },

  downloadDocument: async (documentId) => {
    return api.get(`/documents/${documentId}/download`, {
      responseType: 'blob',
      timeout: 10000,
    });
  }
};

export const referenceService = {
  getCVSUCourses: async () => {
    return api.get('/references/courses');
  }
};

export const getUserToken = () => {
  const { accessToken } = getAuthTokens();
  return accessToken;
};

export const documentRequestService = {
  getAvailableDocumentTypes: async () => {
    try {
      const response = await api.get('/document-requests/available-types');
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('Error fetching available document request types:', error);
      return {
        success: false,
        error: error.response?.data?.detail || error.message
      };
    }
  },

  createDocumentRequest: async (documentType, purpose) => {
    try {
      const response = await api.post(`/document-requests/`, {
        document_type: documentType,
        purpose: purpose
      });
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('Error creating document request:', error);
      return {
        success: false,
        error: error.response?.data?.detail || error.message
      };
    }
  },
  
  getDocumentRequests: async (status = null) => {
    try {
      const url = status ? `/document-requests/?status=${status}` : '/document-requests/';
      const response = await api.get(url);
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('Error fetching document requests:', error);
      return {
        success: false,
        error: error.response?.data?.detail || error.message
      };
    }
  },
  
  getDocumentRequest: async (requestId) => {
    try {
      const response = await api.get(`/document-requests/${requestId}`);
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error(`Error fetching document request ${requestId}:`, error);
      return {
        success: false,
        error: error.response?.data?.detail || error.message
      };
    }
  },
  
  downloadGeneratedDocument: async (requestId, filename) => {
    try {
      const response = await api.get(`/document-requests/${requestId}/download`, {
        responseType: 'blob'
      });

      const contentDisposition = response.headers['content-disposition'] || '';
      const contentType = response.headers['content-type'] || response.data?.type || 'application/octet-stream';
      const headerFilenameMatch = contentDisposition.match(/filename\*?=(?:UTF-8''|")?([^";]+)/i);
      const fallbackExtension = contentType.includes('pdf')
        ? '.pdf'
        : contentType.includes('wordprocessingml')
          ? '.docx'
          : contentType.includes('msword')
            ? '.doc'
            : '';
      const resolvedFilename = headerFilenameMatch
        ? decodeURIComponent(headerFilenameMatch[1].replace(/"/g, '').trim())
        : (filename || `document-${requestId}${fallbackExtension}`);

      const url = window.URL.createObjectURL(new Blob([response.data], { type: contentType }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', resolvedFilename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      return {
        success: true
      };
    } catch (error) {
      let errorMessage = error.response?.data?.detail || error.message;
      if (error.response?.data instanceof Blob) {
        try {
          const rawText = await error.response.data.text();
          const parsed = JSON.parse(rawText);
          errorMessage = parsed.detail || parsed.message || rawText || errorMessage;
        } catch (_blobParseError) {
          // Keep the original message when the blob payload is not JSON.
        }
      }
      console.error(`Error downloading document for request ${requestId}:`, error);
      return {
        success: false,
        error: errorMessage
      };
    }
  }
};

export const adminDocumentRequestService = {
  getAllDocumentRequests: async (status = null) => {
    try {
      const url = status ? `/document-requests/admin?status=${status}` : '/document-requests/admin';
      const response = await api.get(url);
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('Error fetching all document requests:', error);
      return {
        success: false,
        error: error.response?.data?.detail || error.message
      };
    }
  },
  
  updateDocumentRequestStatus: async (requestId, status, adminNotes = null, rejectionReason = null) => {
    try {
      const update = { status };
      
      if (adminNotes) {
        update.admin_notes = adminNotes;
      }
      
      if (rejectionReason) {
        update.rejection_reason = rejectionReason;
      }
      
      const response = await api.put(`/document-requests/${requestId}/update`, update);
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error(`Error updating document request ${requestId}:`, error);
      return {
        success: false,
        error: error.response?.data?.detail || error.message
      };
    }
  },
  
  generateDocument: async (requestId) => {
    try {
      const response = await api.post(`/document-requests/${requestId}/generate`);
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error(`Error generating document for request ${requestId}:`, error);
      return {
        success: false,
        error: error.response?.data?.detail || error.message
      };
    }
  }
};

export const adminDocumentService = {
  searchDocuments: async (statusFilter = 'all') => {
    try {
      let endpoint = `/documents/search`;
      if (statusFilter !== 'all') {
        endpoint += `?verification_status=${statusFilter}`;
      }
      
      const response = await api.get(endpoint);
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('Error searching documents:', error);
      return {
        success: false,
        error: error.response?.data?.detail || error.message
      };
    }
  },
  
  getDocument: async (documentId) => {
    try {
      const response = await api.get(`/documents/${documentId}`);
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error(`Error fetching document ${documentId}:`, error);
      return {
        success: false,
        error: error.response?.data?.detail || error.message
      };
    }
  }
};

export default api; 
