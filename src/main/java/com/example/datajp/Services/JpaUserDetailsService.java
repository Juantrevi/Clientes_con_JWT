package com.example.datajp.Services;

import com.example.datajp.Entities.Role;
import com.example.datajp.Entities.Usuario;
import com.example.datajp.Repository.IUsuarioDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service("jpaUserDetailsService")
public class JpaUserDetailsService implements UserDetailsService {

    @Autowired
    private IUsuarioDao usuarioDao;

    private Logger logger = LoggerFactory.getLogger(JpaUserDetailsService.class);


    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = usuarioDao.findByUsername(username);

        if (usuario == null){
            logger.error("Error en el Login: no existe el usuario: " + username + " En el sistema");
            throw new UsernameNotFoundException("Username: " + username + " no existe en el sistema");
        }


        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

        for (Role role: usuario.getRoles()){
            logger.info("Role: " + role.getAuthority());
            authorities.add(new SimpleGrantedAuthority(role.getAuthority()));
        }

        if (authorities.isEmpty()){
            logger.error("Error en el Login: Usuario " + username + " no tiene roles asignados");
            throw new UsernameNotFoundException("Error en el Login: usuario " + username + " no tiene roles asinados");
        }

        return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true, true, authorities);
    }
}
