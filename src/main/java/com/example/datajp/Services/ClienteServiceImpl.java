package com.example.datajp.Services;

import com.example.datajp.Entities.Factura;
import com.example.datajp.Entities.Producto;
import com.example.datajp.Repository.IClienteDao;
import com.example.datajp.Entities.Cliente;
import com.example.datajp.Repository.IFacturaDao;
import com.example.datajp.Repository.IproductoDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service //Un unico punto de acceso a DAOS o REPOSITORIES
public class ClienteServiceImpl implements IClienteService{

    @Autowired
    private IClienteDao clienteDao;
    @Autowired
    private IproductoDao productoDao;
    @Autowired
    private IFacturaDao facturaDao;

    @Transactional(readOnly = true)
    @Override
    public List<Cliente> findAll() {
        return (List<Cliente>) clienteDao.findAll();
    }


    @Transactional
    @Override
    public void save(Cliente cliente) {
        clienteDao.save(cliente);
    }


    @Transactional
    @Override
    public Cliente findOne(Long id) {
        return clienteDao.findById(id).orElse(null);
    }


    @Override
    @Transactional(readOnly = true)
    public Cliente fetchByIdWithFacturas(Long id) {
        return clienteDao.fetchByIdWithFacturas(id);
    }


    @Transactional
    @Override
    public void delete(Long id) {
        clienteDao.deleteById(id);
    }


    @Transactional(readOnly = true)
    @Override
    public Page<Cliente> findAll(Pageable pageable) {

        return clienteDao.findAll(pageable);
    }


    @Transactional(readOnly = true)
    @Override
    public List<Producto> findByNombreLikeIgnoreCase(String term) {

        return productoDao.findByNombreLikeIgnoreCase("%" + term + "%");
    }


    @Override
    @Transactional
    public void saveFactura(Factura factura) {
        facturaDao.save(factura);
    }


    @Override
    @Transactional(readOnly = true)
    public Producto findProductoById(Long id) {
        return productoDao.findById(id).orElse(null);
    }


    @Override
    @Transactional(readOnly = true)
    public Factura findFacturaById(Long id) {
        return facturaDao.findById(id).orElse(null);
    }


    @Override
    @Transactional
    public void deleteFactura(Long id) {
        facturaDao.deleteById(id);
    }


    @Override
    @Transactional(readOnly = true)
    public Factura fetchByIdWithClienteWithItemFacturaWithProducto(Long id) {
        return facturaDao.fetchByIdWithClienteWithItemFacturaWithProducto(id);
    }


}
