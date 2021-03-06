package br.org.generation.ProjetoBlog.model;

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;


@Entity
@Table(name = "tb_tema")
public class Tema {
    
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	
	
	private String descricao;
	
	//Foreign Key
	@OneToMany(mappedBy = "tema" , cascade = CascadeType.ALL)
     @JsonIgnoreProperties("tema")
	private List<Postagens> postagens;
	
	
	
	
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	public String getDescricao() {
		return descricao;
	}
	public void setDescricao(String descricao) {
		this.descricao = descricao;
	}
	public List<Postagens> getPostagens() {
		return postagens;
	}
	public void setPostagens(List<Postagens> postagens) {
		this.postagens = postagens;
	}
	
}
